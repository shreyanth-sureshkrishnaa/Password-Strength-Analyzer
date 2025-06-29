import math
import time
import re

# Here, we load a common password list, rockyou.txt, and a dictionary wordlist. 
def loadCommonPasswords(filepath="rockyou.txt"):
    with open(filepath, encoding='utf-8', errors='ignore') as file:
        return set(line.strip().lower() for line in file)
    
def loadDictionaryWords(filepath="words_alpha.txt"):
    with open(filepath, encoding='utf-8', errors='ignore') as file:
        return set(line.strip().lower() for line in file if len(line.strip()) >= 4)
    
# This is a leetspeak normalizer. This factors in common ways of mangling a password.
# For example:
#'password123' -> 'p455w0rd123'

def normalizeLeetspeak(password):
    substitutions = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}

    for leet,normal in substitutions.items():
        password = password.replace(leet,normal)
    
    return password.lower()

# Checks if the password contains any words which can be found in a system dictionary.
def containsDictionaryWord(password, wordlist):
    password = normalizeLeetspeak(password)
    for word in wordlist:
        if len(word) >= 4 and word in password:
            return True
    return False

# Checks if the password is in a common password list.
def isCommonPassword(password, commonPasswords):
    normalized = normalizeLeetspeak(password)
    return normalized in commonPasswords

# How difficult it is to crack a certain password depends on it's Character Set Size.
# What different kinds of characters are you using in your passwords? The more unique and diverse, the better. 
# A mix of lowercase letters, uppercase letters, digits and special characters make a password more difficult to crack.
# Password length also plays a major role. Length will be handled in the Entropy section of the code. 

def getCharsetSize(password):
    size = 0

    if any(c.islower() for c in password): #If any lowercase characters are in the password
        size += 26

    if any(c.isupper() for c in password): #Uppercase letters
        size += 26

    if any(c.isdigit() for c in password): #Decimal Digits
        size+= 10

    if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password): #Special Characters
        size += 32

    return size

# Entropy Calculation:
# The 'Entropy' of a password is a measure of how unpredictable or random it is. 
# Mathematically, entropy = length of password x log2(Size of Character Set). It is measured in bits. 

def getEntropy(password):
    charsetSize = getCharsetSize(password)
    entropy = len(password) * math.log2(charsetSize)
    return entropy, charsetSize

# Classical Computer Crack Time: Brute Force Approximation

def classicalCrackTime(entropy, guessesPerSecond = 1e9):
    combinations = 2**entropy
    crackTime = combinations/guessesPerSecond
    return crackTime

# Quantum Computer Crack Time: The Grover's Algorithm Approximation

def quantumCrackTime(entropy, guessesPerSecond = 1e9):
    combinations = 2**entropy
    crackTime = math.sqrt(combinations)/guessesPerSecond
    return crackTime


# Modern Crack Time checks the password's integrity with a list of english dictionary words, and the infamous rockyou.txt password list. 
def modernCrackTime(password, commonPasswords, dictionaryWords):
    normalized = normalizeLeetspeak(password)

    # 1. Very common password inside the rockyou.txt file. 
    if normalized in commonPasswords:
        return 0.5  # Instant crac
    
    # 2. Contains dictionary word (even with substitutions)
    if containsDictionaryWord(password, dictionaryWords):
        # If it's just a word + 123, 1, !, or anything else, it's still weak. 
        if re.search(r"(123|[!@#$%^&*]+|[0-9]{1,4})$", password):
            return 30 
        return 90  

    # 3. Detecting keyboard or common date-based patterns. Again, all estimates. 
    if re.search(r"(qwerty|asdf|zxcv|pass|love|god|admin|user)", normalized):
        return

    if re.search(r"(19[0-9]{2}|20[0-4][0-9])", password):
        return 45 

    if re.fullmatch(r"[a-z]{4,}\d{2,4}", normalized):
        return 60

    # If the password has a structure like "WordWordNumber"
    if re.fullmatch(r"[a-z]{4,}[A-Z]{1}[a-z]*\d{1,4}", password):
        return 120  # harder, but still guessable

    # Fallback
    entropy, _ = getEntropy(password)
    return classicalCrackTime(entropy, guessesPerSecond=1e10)  # modern GPUs are fast!
# A basic time formatter. 

def timeFormat(seconds):
    if seconds < 4:
        return f"{seconds:.4f} seconds"
    units = ['seconds', 'minutes', 'hours', 'days', 'years', 'centuries']
    factors = [60,60,24,365,100]
    i = 0

    while i < len(factors) and seconds >= factors[i]:
        seconds /= factors[i]
        i += 1

    return f"{seconds:.2f} {units[i]}"
    
# The actual analyze function with markdown and stuff still attached. 

def analyze(password, commonPasswords, dictionaryWords, st):
    if isCommonPassword(password, commonPasswords):
        st.error("Very Common Password: found in rockyou.txt")
    elif containsDictionaryWord(password, dictionaryWords):
        st.warning("Contains a dictionary word")
    else:
        st.success("No dictionary or common patterns found")

    entropy, charset = getEntropy(password)
    classical = classicalCrackTime(entropy)
    quantum = quantumCrackTime(entropy)
    modern = modernCrackTime(password, commonPasswords, dictionaryWords)

    st.metric("Charset Size", f"{charset} characters")
    st.metric("Entropy", f"{entropy:.2f} bits")

    st.markdown("### 🖥️ Estimated Crack Times")
    st.info(f"Classical: `{timeFormat(classical)}`")
    st.info(f"Quantum: `{timeFormat(quantum)}`")
    st.info(f"Modern: `{timeFormat(modern)}`")


# MAIN: 

if __name__ == "__main__":

    commonPasswords = loadCommonPasswords("rockyou.txt")
    dictionaryWords = loadDictionaryWords("words_alpha.txt")  # or use /usr/share/dict/words

    password = input("Enter a password to analyze: ")
    analyze(password, commonPasswords, dictionaryWords)

