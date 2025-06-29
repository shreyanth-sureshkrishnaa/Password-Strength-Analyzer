import streamlit as st
import time

# Page Setup
st.set_page_config(page_title="🔐 Password Strength Analyzer", layout="centered")
st.title("Password Strength Estimator")
st.caption("Designed and developed by Shreyanth Suresh Krishnaa · [Connect with me on LinkedIn!](https://www.linkedin.com/in/shreyanthsureshkrishnaa)")
st.markdown("Check how strong your password is against classical brute-force, quantum brute-force, and modern attacks.")

# Here, we import the logic. 
from main import (
    loadCommonPasswords,
    loadDictionaryWords,
    normalizeLeetspeak,
    isCommonPassword,
    containsDictionaryWord,
    getEntropy,
    getCharsetSize,
    classicalCrackTime,
    quantumCrackTime,
    modernCrackTime,
    timeFormat
)


@st.cache_data(show_spinner=False)
def loadLists():
    return loadCommonPasswords("rockyou.txt"), loadDictionaryWords("words_alpha.txt")

with st.spinner("Loading up wordlists..."):
    commonPasswords, dictionaryWords = loadLists()



password = st.text_input("Enter a password to analyze:", type="password")


# Analysis begins when the button is clicked. 
if st.button("🔍 Analyze Password") and password:
    with st.spinner("🔍 Analyzing password..."):

        st.divider()
        st.subheader("Analysis")

        normalized = normalizeLeetspeak(password)

        if isCommonPassword(password, commonPasswords):
            st.error("Very Common Password: found in rockyou.txt; cracked instantly!")
        elif containsDictionaryWord(password, dictionaryWords):
            st.warning("Contains a dictionary word; easily guessable with wordlists.")
        else:
            st.success("No obvious dictionary or common password patterns detected.")

        
        entropy, charset = getEntropy(password)
        classical = classicalCrackTime(entropy)
        quantum = quantumCrackTime(entropy)
        modern = modernCrackTime(password, commonPasswords, dictionaryWords)

        
        col1, col2 = st.columns(2)

        
        with col1:
            st.subheader("🔤 Charset & Entropy")
            st.metric("Charset Size", f"{charset} characters")
            st.metric("Entropy", f"{entropy:.2f} bits")
            strength = min(int(entropy / 1.5), 100)  # Scale entropy to 0–100
            st.markdown("### Password Strength Meter")
            st.progress(strength)
        
        with col2:
            st.subheader("⏰Estimated Crack Times")
            st.info(f"🧮 Classical Brute Force: `{timeFormat(classical)}`")
            st.info(f"⚛️ Quantum Brute Force: `{timeFormat(quantum)}`")
            st.info(f"⚙️ Modern Wordlists: `{timeFormat(modern)}`")

        st.caption("Note: Real-world attackers often use hybrid wordlist + pattern attacks. Crack times are estimates.")
        st.caption("Also, most systems have rate limiting and lockout mechanisms. It's important to remember that social engineering is much more effective and dangerous than brute force. Stay vigilant.")
        st.divider()
        