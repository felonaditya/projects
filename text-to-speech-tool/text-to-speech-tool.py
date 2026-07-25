from os import environ
environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'

# Import required libraries
from gtts import gTTS
from io import BytesIO
import pygame
from langdetect import detect, DetectorFactory
import re
import math
import time

# Fix langdetect for consistent results
DetectorFactory.seed = 0

# Initialize pygame mixer
pygame.mixer.init()

# Reading speed configuration
WPM = 130

# Language mapping for gTTS compatibility
LANGUAGE_MAP = {
    'is':  'is',
    'no':  'no', 'nb': 'no', 'nn': 'no', 'da': 'da', 'sv': 'sv',
    'sl':  'hr', 'hr': 'hr', 'sr': 'sr', 'cs': 'cs', 'sk': 'sk', 'pl': 'pl',
    'mk':  'ru', 'iw': 'he', 'tl': 'fil', 'fi': 'fi', 'hu': 'hu',
    'ro':  'ro', 'bg': 'bg', 'uk': 'uk'
}

def detect_language(text):
    """Detect text language with special Icelandic check"""
    try:
        lang = detect(text)
        if lang in ['no', 'nb', 'nn'] and ('ð' in text or 'þ' in text or 'æ' in text):
            lang = 'is'
        return LANGUAGE_MAP.get(lang, lang)
    except:
        return 'en'

def speak_gtts(text, lang_code):
    """Generate speech with gTTS and play via pygame mixer"""
    try:
        tts_stream = BytesIO()
        tts = gTTS(text=text, lang=lang_code, slow=False)
        tts.write_to_fp(tts_stream)
        tts_stream.seek(0)
        
        pygame.mixer.music.load(tts_stream, 'mp3')
        pygame.mixer.music.play()
        
        while pygame.mixer.music.get_busy():
            pygame.time.Clock().tick(10)
            
    except Exception as e:
        try:
            print(f"gTTS {lang_code} failed, trying English: {e}")
            tts_stream = BytesIO()
            tts = gTTS(text=text, lang='en', slow=False)
            tts.write_to_fp(tts_stream)
            tts_stream.seek(0)
            pygame.mixer.music.load(tts_stream, 'mp3')
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                pygame.time.Clock().tick(10)
        except Exception as e2:
            print(f"gTTS error (both failed): {e2}")

def split_sentences(text):
    """Split input text into sentences"""
    sentences = re.split(r'(?<=[.!?])\s+', text)
    return [s.strip() for s in sentences if s.strip()]

def calculate_dynamic_delay(sentence, total_words):
    """Calculate fast minimal pause between sentences"""
    words = len(sentence.split())
    base_duration = (words / WPM) * 60
    proportion = words / total_words if total_words else 1
    return max(0.3, base_duration * 0.02)

def main():
    """Main loop - read text input and speak sentences"""
    while True:
        text = input("Enter your text: ").strip()
        if text.lower() == 'exit':
            break
        if not text:
            continue
            
        lang = detect_language(text)
        print(f"Detected language: {lang}")
        
        sentences = split_sentences(text)
        total_words = sum(len(s.split()) for s in sentences)
        
        for sentence in sentences:
            speak_gtts(sentence, lang)
            delay = calculate_dynamic_delay(sentence, total_words)
            time.sleep(delay)
        time.sleep(0.05)

if __name__ == "__main__":
    main()