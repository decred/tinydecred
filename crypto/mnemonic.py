"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, The Decred developers
See LICENSE for details

PGP-based mnemonic seed generation. 
"""
from tinydecred.crypto.crypto import sha256ChecksumByte
from tinydecred.crypto.bytearray import ByteArray

alternatingWords = """aardvark
adroitness
absurd
adviser
accrue
aftermath
acme
aggregate
adrift
alkali
adult
almighty
afflict
amulet
ahead
amusement
aimless
antenna
Algol
applicant
allow
Apollo
alone
armistice
ammo
article
ancient
asteroid
apple
Atlantic
artist
atmosphere
assume
autopsy
Athens
Babylon
atlas
backwater
Aztec
barbecue
baboon
belowground
backfield
bifocals
backward
bodyguard
banjo
bookseller
beaming
borderline
bedlamp
bottomless
beehive
Bradbury
beeswax
bravado
befriend
Brazilian
Belfast
breakaway
berserk
Burlington
billiard
businessman
bison
butterfat
blackjack
Camelot
blockade
candidate
blowtorch
cannonball
bluebird
Capricorn
bombast
caravan
bookshelf
caretaker
brackish
celebrate
breadline
cellulose
breakup
certify
brickyard
chambermaid
briefcase
Cherokee
Burbank
Chicago
button
clergyman
buzzard
coherence
cement
combustion
chairlift
commando
chatter
company
checkup
component
chisel
concurrent
choking
confidence
chopper
conformist
Christmas
congregate
clamshell
consensus
classic
consulting
classroom
corporate
cleanup
corrosion
clockwork
councilman
cobra
crossover
commence
crucifix
concert
cumbersome
cowbell
customer
crackdown
Dakota
cranky
decadence
crowfoot
December
crucial
decimal
crumpled
designing
crusade
detector
cubic
detergent
dashboard
determine
deadbolt
dictator
deckhand
dinosaur
dogsled
direction
dragnet
disable
drainage
disbelief
dreadful
disruptive
drifter
distortion
dropper
document
drumbeat
embezzle
drunken
enchanting
Dupont
enrollment
dwelling
enterprise
eating
equation
edict
equipment
egghead
escapade
eightball
Eskimo
endorse
everyday
endow
examine
enlist
existence
erase
exodus
escape
fascinate
exceed
filament
eyeglass
finicky
eyetooth
forever
facial
fortitude
fallout
frequency
flagpole
gadgetry
flatfoot
Galveston
flytrap
getaway
fracture
glossary
framework
gossamer
freedom
graduate
frighten
gravity
gazelle
guitarist
Geiger
hamburger
glitter
Hamilton
glucose
handiwork
goggles
hazardous
goldfish
headwaters
gremlin
hemisphere
guidance
hesitate
hamlet
hideaway
highchair
holiness
hockey
hurricane
indoors
hydraulic
indulge
impartial
inverse
impetus
involve
inception
island
indigo
jawbone
inertia
keyboard
infancy
kickoff
inferno
kiwi
informant
klaxon
insincere
locale
insurgent
lockup
integrate
merit
intention
minnow
inventive
miser
Istanbul
Mohawk
Jamaica
mural
Jupiter
music
leprosy
necklace
letterhead
Neptune
liberty
newborn
maritime
nightbird
matchmaker
Oakland
maverick
obtuse
Medusa
offload
megaton
optic
microscope
orca
microwave
payday
midsummer
peachy
millionaire
pheasant
miracle
physique
misnomer
playhouse
molasses
Pluto
molecule
preclude
Montana
prefer
monument
preshrunk
mosquito
printer
narrative
prowler
nebula
pupil
newsletter
puppy
Norwegian
python
October
quadrant
Ohio
quiver
onlooker
quota
opulent
ragtime
Orlando
ratchet
outfielder
rebirth
Pacific
reform
pandemic
regain
Pandora
reindeer
paperweight
rematch
paragon
repay
paragraph
retouch
paramount
revenge
passenger
reward
pedigree
rhythm
Pegasus
ribcage
penetrate
ringbolt
perceptive
robust
performance
rocker
pharmacy
ruffled
phonetic
sailboat
photograph
sawdust
pioneer
scallion
pocketful
scenic
politeness
scorecard
positive
Scotland
potato
seabird
processor
select
provincial
sentence
proximate
shadow
puberty
shamrock
publisher
showgirl
pyramid
skullcap
quantity
skydive
racketeer
slingshot
rebellion
slowdown
recipe
snapline
recover
snapshot
repellent
snowcap
replica
snowslide
reproduce
solo
resistor
southward
responsive
soybean
retraction
spaniel
retrieval
spearhead
retrospect
spellbind
revenue
spheroid
revival
spigot
revolver
spindle
sandalwood
spyglass
sardonic
stagehand
Saturday
stagnate
savagery
stairway
scavenger
standard
sensation
stapler
sociable
steamship
souvenir
sterling
specialist
stockman
speculate
stopwatch
stethoscope
stormy
stupendous
sugar
supportive
surmount
surrender
suspense
suspicious
sweatband
sympathy
swelter
tambourine
tactics
telephone
talon
therapist
tapeworm
tobacco
tempest
tolerance
tiger
tomorrow
tissue
torpedo
tonic
tradition
topmost
travesty
tracker
trombonist
transit
truncated
trauma
typewriter
treadmill
ultimate
Trojan
undaunted
trouble
underfoot
tumor
unicorn
tunnel
unify
tycoon
universe
uncut
unravel
unearth
upcoming
unwind
vacancy
uproot
vagabond
upset
vertigo
upshot
Virginia
vapor
visitor
village
vocalist
virus
voyager
Vulcan
warranty
waffle
Waterloo
wallet
whimsical
watchword
Wichita
wayside
Wilmington
willow
Wyoming
woodlark
yesteryear
Zulu
Yucatan"""


def pgWords():
	wordList = alternatingWords.split("\n")
	idxMap = {}
	for i, word in enumerate(wordList):
		idxMap[word.lower()] = i
	return wordList, idxMap

def encode(seed):
	"""
	Encode the seed to a mnemonic seed.

	Args:
		seed (ByteArray): The seed to encode.

	Returns:
		list(str): A mnemonic seed.
	"""
	if isinstance(seed, ByteArray):
		seed = seed.bytes()
	wordList, _ = pgWords()
	def byteToMnemonic(b, i):
		bb = b * 2
		if i%2 != 0:
			bb += 1
		return wordList[bb]

	words = [""]*(len(seed)+1)
	for i, b in enumerate(seed):
		words[i] = byteToMnemonic(b, i)
	checksum = sha256ChecksumByte(seed)
	words[len(words)-1] = byteToMnemonic(checksum, len(seed))
	return words

def decode(words):
	"""
	DecodeMnemonics returns the decoded value that is encoded by words.  Any
	words that are whitespace are empty are skipped.
	"""
	_, byteMap = pgWords()
	decoded = [0]*len(words)
	idx = 0
	for word in words:
		word = word.strip().lower()
		if word == "":
			continue
		if word not in byteMap:
			raise Exception("unknown words in mnemonic key: %s" % word)
		b = byteMap[word]
		if int(b%2) != idx%2:
			raise Exception("word %v is not valid at position %v, check for missing words" % (w, idx))
		decoded[idx] = b // 2
		idx += 1
	return ByteArray(decoded[:idx])

import unittest
class TestMnemonic(unittest.TestCase):
	def test_all(self):
		tests = [
			(
				"topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless",
				ByteArray([
					0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48,
					0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC, 0x52, 0x8F, 0xD7,
					0xFA, 0x3F, 0x19
				]),
			),
			(
				"stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade",
				ByteArray([
					0xD1, 0xD4, 0x64, 0xC0, 0x04, 0xF0, 0x0F, 0xB5,
					0xC9, 0xA4, 0xC8, 0xD8, 0xE4, 0x33, 0xE7, 0xFB, 0x7F,
					0xF5, 0x62, 0x56
				]),
			),
		]
		listToLower = lambda l: [x.lower() for x in l]
		for i, (words, seed) in enumerate(tests):
			unWords = encode(seed)
			self.assertListEqual(listToLower(unWords[:len(unWords)-1]), listToLower(words.split()))
			unSeed = decode(words.split())
			self.assertEqual(seed, unSeed)
