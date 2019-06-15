from tinydecred.crypto import opcode

NonStandardTy      = 0  # None of the recognized forms.
PubKeyTy           = 1  # Pay pubkey.
PubKeyHashTy       = 2  # Pay pubkey hash.
ScriptHashTy       = 3  # Pay to script hash.
MultiSigTy         = 4  # Multi signature.
NullDataTy         = 5  # Empty data-only (provably prunable).
StakeSubmissionTy  = 6  # Stake submission.
StakeGenTy         = 7  # Stake generation
StakeRevocationTy  = 8  # Stake revocation.
StakeSubChangeTy   = 9  # Change for stake submission tx.
PubkeyAltTy        = 10 # Alternative signature pubkey.
PubkeyHashAltTy    = 11 # Alternative signature pubkey hash.

# DefaultScriptVersion is the default scripting language version
# representing extended Decred script.
DefaultScriptVersion = 0



def getScriptClass(version, script):
	"""
	GetScriptClass returns the class of the script passed.
	NonStandardTy will be returned when the script does not parse.
	"""
	if version != DefaultScriptVersion:
		return NonStandardTy

	return typeOfScript(version, script)

def typeOfScript(scriptVersion, script):
	"""
	scriptType returns the type of the script being inspected from the known
	standard types.
		
	NOTE:  All scripts that are not version 0 are currently considered non
	standard.
	"""
	if scriptVersion != DefaultScriptVersion:
		return NonStandardTy
	# if isPubKeyScript(script):
	# 	return PubKeyTy
	# if isPubKeyAltScript(script):
	# 	return PubkeyAltTy
	if isPubKeyHashScript(script):
		return PubKeyHashTy
	# if isPubKeyHashAltScript(script):
	# 	return PubkeyHashAltTy
	# if isScriptHashScript(script):
	# 	return ScriptHashTy
	# if isMultisigScript(scriptVersion, script):
	# 	return MultiSigTy
	# if isNullDataScript(scriptVersion, script):
	# 	return NullDataTy
	# if isStakeSubmissionScript(scriptVersion, script):
	# 	return StakeSubmissionTy
	# if isStakeGenScript(scriptVersion, script):
	# 	return StakeGenTy
	# if isStakeRevocationScript(scriptVersion, script):
	# 	return StakeRevocationTy
	# if isStakeChangeScript(scriptVersion, script):
	# 	return StakeSubChangeTy
	return NonStandardTy

def isPubKeyHashScript(script):
	return not extractPubKeyHash(script) is None

def extractPubKeyHash(script):
	"""
	extractPubKeyHash extracts the public key hash from the passed script if it
	is a standard pay-to-pubkey-hash script.  It will return nil otherwise.
	"""
	# A pay-to-pubkey-hash script is of the form:
	# OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
	if (len(script) == 25 and
		script[0] == opcode.OP_DUP and
		script[1] == opcode.OP_HASH160 and
		script[2] == opcode.OP_DATA_20 and
		script[23] == opcode.OP_EQUALVERIFY and
		script[24] == opcode.OP_CHECKSIG):

		return script[3:23]
	return None