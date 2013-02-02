import Text.ParserCombinators.Parsec
import Data.IntSet (IntSet)
import qualified Data.IntSet as IS
import Numeric
import Data.Char (isSpace)

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
	return (map fst b, concat $ map snd b)

pKeyBlock :: GenParser Char st (Key, [Signature])
pKeyBlock = do
	(kid, kr, ke) <- pPubLine
	optional pRevLine
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
	many pRevLine
	sl <- many (try $ do
		s <- pSigLine
		many pRevLine
		return s)
	return (uid, sl)

pSigLine :: GenParser Char st (Int, Bool, KeyID)
pSigLine = do
	string "sig"
	anyChar
	l <- anyChar
	anyChar
	anyChar
	r <- anyChar
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
	return (if l == ' ' then 0 else read [l], if r == 'R' then True else False, k)

pUIDLine :: GenParser Char st UID
pUIDLine = do
	string "uid"
	spaces
	uid <- manyTill anyChar newline
	return uid

pUID :: GenParser Char st (Maybe UID)
pUID = choice [string "[User ID not found]" >> newline >> return Nothing, manyTill anyChar newline >>= return . Just]


pPubLine :: GenParser Char st (KeyID, Bool, Bool)
pPubLine = do
	string "pub"
	spaces
	skipMany digit
	upper
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
		string " [expires: "
		manyTill anyChar $ char ']'
	newline
	return (k, r, e)

pKey = many hexDigit

pRevLine :: GenParser Char st ()
pRevLine = do
	string "rev"
	manyTill anyChar newline
	return ()

pDate :: GenParser Char st ()
pDate = (many1 $ choice [char '-', digit]) >> return ()

trim :: String -> String
trim      = f . f
   where f = reverse . dropWhile isSpace

drawKey :: Key -> String
drawKey k = "\"" ++ (kid k) ++ "\" [label=\"" ++ (trim $ takeWhile (/= '<') $ head $ kuids k) ++ "\"]\n"

drawSig :: Signature -> String
drawSig s = "{ " ++ show (skey s) ++ " } -> \"" ++ (tkey s) ++ "\" [color=\"" ++ color ++ "\",penwidth=\"" ++ (show (1 + level s)) ++ "\"]\n"

	where	color = case level s of
				0 -> "black"
				1 -> "grey"
				2 -> "blue"
				3 -> "green"
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
	let Right (ks, ss) = parse pAll "" stdin
	putStrLn "digraph \"Keyring Statistics\" {"
	putStrLn "overlap=scale"
	putStrLn "splines=true"
	putStrLn "sep=.1"
	let keys = filterKeys ks
	putStr $ concatMap drawKey $ keys
	putStr $ concatMap drawSig $ filterSigs keys ss
	putStrLn "}"
