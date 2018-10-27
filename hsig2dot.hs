import Control.Monad
import Data.Char (isSpace)
import Data.Either
import Data.IntSet (IntSet)
import qualified Data.IntSet as IS
import Data.List
import Numeric
import Text.ParserCombinators.Parsec

data Key = Key {
	kid :: KeyID,
	kuids :: [UID],
	krevoked :: Bool,
	kexpired :: Bool
} deriving Show

type KeyID = String
type UID = String

data Signature = Signature {
	skey :: KeyID,
	tkey :: KeyID,
	uid :: UID,
	level :: Int,
	srevoked :: Bool
} deriving Show

pAll :: GenParser Char st ([Key], [Signature])
pAll = do
	-- FIXME better approach
	manyTill anyChar newline
	manyTill anyChar newline
	b <- many $ try pKeyBlock
	eof
	return (map fst b, concatMap snd b)

pKeyBlock :: GenParser Char st (Key, [Signature])
pKeyBlock = do
	(kid, kr, ke) <- pPubLine
	optional pFingerprint
	optional pRevLine
	optional pRevReason
	uids <- many $ try pUIDBlock
	optional pSubBlocks
	newline
	return (Key kid (map fst uids) kr ke, map (\(u, l, r, k) -> Signature k kid u l r) $ concatMap (\(u, ss) -> map (\(l, r, k) -> (u, l, r, k)) ss) uids)

pSubBlocks :: GenParser Char st ()
pSubBlocks = do
	string "sub"
	manyTill anyChar (lookAhead (try (newline >> newline)))
	newline
	return ()

pUIDBlock :: GenParser Char st (UID, [(Int, Bool, KeyID)])
pUIDBlock = do
	uid <- pUIDLine
	sl <- many (try $ do
		(l, k) <- pSigLine
		r <- many pRevLine
		return ((l, False, k), r))
	return (uid, revoke (reverse sl) [])
	where	revoke [] _ = []
		revoke ((s@(l, r, k), rl):xs) revlist = 
			let	nrl = revlist ++ rl
				(rrl, ns) = if k `elem` nrl then (delete k nrl, (l, True, k)) else (nrl, s) in
			ns : revoke xs rrl

pSigLine :: GenParser Char st (Int, KeyID)
pSigLine = do
	string "sig"
	anyChar
	l <- anyChar
	anyChar
	anyChar
	anyChar
	anyChar
	anyChar
	anyChar
	anyChar
	anyChar
	k <- pKey
	space
	pDate
	space
	space
	u <- pUID
	return (if l == ' ' then 0 else read [l], k)

pUIDLine :: GenParser Char st UID
pUIDLine = do
	string "uid"
	spaces
	manyTill anyChar newline

pUID :: GenParser Char st (Maybe UID)
pUID = choice [string "[User ID not found]" >> newline >> return Nothing, liftM Just $ manyTill anyChar newline]


pPubLine :: GenParser Char st (KeyID, Bool, Bool)
pPubLine = do
	string "pub"
	spaces
	skipMany lower
	skipMany digit
	char '/'
	k <- pKey
	space
	pDate
	r <- option False $ try $ do
		string " [revoked: "
		manyTill anyChar $ char ']'
		return True
	e <- option False $ try $ do
		string " [expired: "
		manyTill anyChar $ char ']'
		return True
	optional $ do
		string " ["
		manyTill anyChar $ char ']'
	newline
	return (k, r, e)

pKey = do
	optional $ string "0x"
	many hexDigit

pRevLine :: GenParser Char st KeyID
pRevLine = do
	string "rev"
	spaces
	k <- pKey
	manyTill anyChar newline
	return k

pRevReason = do
	spaces
	string "reason for revocation: "
	manyTill anyChar newline

pFingerprint = do
	spaces
	string "Key fingerprint = "
	manyTill anyChar newline

pDate :: GenParser Char st ()
pDate = void $ many1 $ choice [char '-', digit]

trim :: String -> String
trim      = f . f
   where f = reverse . dropWhile isSpace

drawKey :: Key -> String
drawKey k = "\"" ++ (kid k) ++ "\" [label=\"" ++ (trim $ takeWhile (/= '<') $ head $ kuids k) ++ "\"]\n"

drawSig :: Signature -> String
drawSig s = "{ " ++ show (skey s) ++ " } -> \"" ++ (tkey s) ++ "\" [color=\"" ++ color ++ "\",penwidth=\"" ++ (show (if srevoked s then 3 else 1 + level s)) ++ "\",weight=\"" ++ show weight ++ "\",arrowhead=empty]\n"

	where	color = if srevoked s then "red" else case level s of
				0 -> "black"
				1 -> "grey"
				2 -> "blue"
				3 -> "green"
		weight = if srevoked s then 0 else case level s of
			1 -> 1
			2 -> 2
			0 -> 3
			3 -> 4

filterKeys :: [Key] -> [Key]
filterKeys = filter (\k -> and [
			not $ krevoked k,
			not $ kexpired k
		])

filterSigs :: [Key] -> [Signature] -> [Signature]
filterSigs keys sigs = let ks = IS.fromList $ map (fst . head . readHex . kid) keys in
	filter (\s -> let	sk = fst $ head $ readHex $ skey s
				tk = fst $ head $ readHex $ tkey s in
	and [
			sk /= tk,
			IS.member sk ks,
			IS.member tk ks
		]) sigs

main = do
	stdin <- getContents
	either print draw $ parse pAll "" stdin

draw (ks, ss) = do
	putStrLn "digraph \"Keyring Statistics\" {"
	putStrLn "overlap=scale"
	putStrLn "splines=true"
	putStrLn "sep=.1"
	let keys = filterKeys ks
	putStr $ concatMap drawKey keys
	putStr $ concatMap drawSig $ filterSigs keys ss
	putStrLn "}"
