# Add this at the top of your app.py, right after the imports
class URLFeatureExtractor:
    def __init__(self):
        self.url_dt_model = DecisionTreeClassifier(max_depth=5, random_state=42)
        self.url_features_trained = False
        self.feature_order = None
    
    def extract_url_features(self, url):
        features = {}
        features['has_url'] = 1 if url else 0
        
        if not url:
            return features
        
        try:
            res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
            features['has_tld'] = 1 if res.tld else 0
            features['primary_domain_length'] = len(res.parsed_url.netloc)
            features['domain_length'] = len(res.parsed_url.netloc)
        except:
            features['has_tld'] = 0
            features['primary_domain_length'] = 0
            features['domain_length'] = 0
        
        special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//','&']
        for char in special_chars:
            features[f'count_{char}'] = url.count(char)
        
        features['abnormal_url'] = self.abnormal_url(url)
        features['https'] = self.http_secure(url)
        features['digits'] = self.digit_count(url)
        features['letters'] = self.letter_count(url)
        features['shortening_service'] = self.shortening_service(url)
        features['having_ip_address'] = self.having_ip_address(url)
        
        parsed = urlparse(url)
        features['url_length'] = len(url)
        features['path_length'] = len(parsed.path)
        features['num_subdomains'] = len(parsed.netloc.split('.')) - 1
        features['has_port'] = 1 if ':' in parsed.netloc else 0
        features['has_redirect'] = 1 if '//' in url[url.find('://')+3:] else 0
        
        features['credential_leak'] = int(bool(re.search(r'(user|pass|login|auth|pwd)=', url.lower())))
        features['suspicious_params'] = self.suspicious_parameters(url)
        features['insecure_http'] = int(parsed.scheme == 'http')
        features['high_special_chars'] = int(sum(url.count(c) for c in ['?','=','&','%']) >= 3)
        features['obfuscation_attempt'] = int(bool(re.search(r'(%[0-9a-f]{2}|[._-]{3,})', url)))
        features['brand_impersonation'] = self.brand_impersonation_check(url)
        
        suspicious_tlds = [
            'xyz', 'top', 'gq', 'ml', 'tk', 'cf', 'ga', 'work', 'support', 'click', 'country',
            'stream', 'gdn', 'racing', 'download', 'xin', 'jetzt', 'mom', 'party', 'date',
            'faith', 'review', 'zip', 'kim', 'cricket', 'science', 'win', 'host', 'men', 'loan'
        ]
        try:
            tld = get_tld(url, fail_silently=True)
            features['suspicious_tld'] = 1 if tld in suspicious_tlds else 0
        except:
            features['suspicious_tld'] = 0
        
        features['hex_url'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
        features['double_slash'] = int(url.count('//') > 1)
        
        return features
    
    def train_url_model(self, X, y):
        X_numeric = X.apply(pd.to_numeric, errors='coerce').fillna(0)
        self.feature_order = list(X_numeric.columns)
        self.url_dt_model.fit(X_numeric, y)
        self.url_features_trained = True
    
    def predict_url(self, url_features):
        if not self.url_features_trained:
            raise ValueError("URL decision tree model not trained yet")
        
        if not self.feature_order:
            raise ValueError("Feature order not set during training")
        
        feature_vector = []
        for feature in self.feature_order:
            feature_vector.append(url_features.get(feature, 0))
        
        feature_vector = np.array(feature_vector, dtype=float).reshape(1, -1)
        
        prediction = self.url_dt_model.predict(feature_vector)[0]
        probability = self.url_dt_model.predict_proba(feature_vector)[0][1]
        
        return {
            'prediction': prediction,
            'probability': probability,
            'features_used': self.feature_order
        }

    def abnormal_url(self, url):
        hostname = urlparse(url).hostname
        if not hostname:
            return 1
        return 0 if hostname in url else 1

    def http_secure(self, url):
        return 1 if urlparse(url).scheme == 'https' else 0

    def digit_count(self, url):
        return sum(1 for c in url if c.isdigit())

    def letter_count(self, url):
        return sum(1 for c in url if c.isalpha())

    def shortening_service(self, url):
        services = [
            'bit\.ly', 'goo\.gl', 'shorte\.st', 'go2l\.ink', 'x\.co', 'ow\.ly', 
            't\.co', 'tinyurl', 'tr\.im', 'is\.gd', 'cli\.gs', 'yfrog\.com', 
            'migre\.me', 'ff\.im', 'tiny\.cc', 'url4\.eu', 'twit\.ac', 'su\.pr', 
            'twurl\.nl', 'snipurl\.com', 'short\.to', 'BudURL\.com', 'ping\.fm', 
            'post\.ly', 'Just\.as', 'bkite\.com', 'snipr\.com', 'fic\.kr', 
            'loopt\.us', 'doiop\.com', 'short\.ie', 'kl\.am', 'wp\.me', 
            'rubyurl\.com', 'om\.ly', 'to\.ly', 'bit\.do', 'lnkd\.in', 'db\.tt', 
            'qr\.ae', 'adf\.ly', 'bitly\.com', 'cur\.lv', 'ity\.im', 'q\.gs', 
            'po\.st', 'bc\.vc', 'twitthis\.com', 'u\.to', 'j\.mp', 'buzurl\.com', 
            'cutt\.us', 'u\.bb', 'yourls\.org', 'prettylinkpro\.com', 'scrnch\.me', 
            'filoops\.info', 'vzturl\.com', 'qr\.net', '1url\.com', 'tweez\.me', 
            'v\.gd', 'link\.zip\.net'
        ]
        return 1 if re.search('|'.join(services), url) else 0

    def having_ip_address(self, url):
        patterns = [
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)',
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.'
            r'(0x[0-9a-fA-F]{1,2})\/)',
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)',
            r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
        ]
        return 1 if any(re.search(p, url) for p in patterns) else 0

    def suspicious_parameters(self, url):
        suspicious = ['user', 'pass', 'login', 'auth', 'token', 'key', 'session']
        query = urlparse(url).query
        return sum(1 for param in suspicious if param in query.lower())

    def brand_impersonation_check(self, url):
        brands = ['paypal', 'bank', 'amazon', 'ebay', 'apple', 'microsoft']
        domain = urlparse(url).netloc
        return 1 if any(brand in domain.lower() for brand in brands) else 0

from flask import Flask, request, jsonify
import joblib
import pickle
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from transformers import BertTokenizer, BertModel
from sentence_transformers import SentenceTransformer
import torch
from sklearn.metrics.pairwise import cosine_similarity
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import os

# Download NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')

app = Flask(__name__)

# Initialize with empty components that will be loaded in load_models()
class PhishingDetectorAPI:
    def __init__(self):
        self.model = None
        self.tfidf = None
        self.url_extractor = None
        self.semantic_analyzer_config = None
        self.tokenizer = None
        self.bert_model = None
        self.sentence_model = None

# Initialize the detector
detector = PhishingDetectorAPI()

# Word lists (same as in your notebook)
URGENT_WORDS = ['urgent', 'immediately', 'now', 'hurry', 'deadline', 'limited time', 'act now', 'right away', 'expire', 'last chance', 'final notice', 'immediate action required', 'response required', 'time sensitive', 'expiring soon', 'limited offer', 'closing soon', 'don\'t delay', 'only today', 'last opportunity', 'final warning', 'action needed', 'attention required', 'quick response', 'rush', 'asap', 'right now', 'without delay', 'instant', 'prompt', 'today only']
TOO_GOOD_WORDS = ['win', 'won', 'prize', 'award', 'free', 'gift', 'bonus', 'selected', 'congratulations', 'reward', 'jackpot', 'lucky', 'winner', 'giveaway', 'million', 'billion', 'cash', 'fortune', 'wealth', 'rich', 'exclusive', 'vip', 'special offer', 'no cost', 'no fee', 'guaranteed', 'risk-free', 'once in a lifetime', 'life-changing', 'miracle', 'amazing', 'incredible', 'unbelievable', 'limited edition', 'secret', 'hidden', 'exclusive']
REQUEST_WORDS = ['verify', 'confirm', 'account', 'password', 'login', 'click', 'update', 'information', 'personal', 'details', 'security', 'credentials', 'validate', 'authenticate', 'renew', 'reactivate', 'unlock', 'suspend', 'restrict', 'compromise', 'hacked', 'breach', 'fraud', 'suspicious', 'activity', 'required', 'necessary', 'mandatory', 'immediately', 'now', 'urgent', 'social security', 'credit card', 'bank account', 'ssn', 'pin', 'dob']

def preprocess_text(text):
    try:
        text = text.lower()
        text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
        text = re.sub(r'\W', ' ', text)
        text = re.sub(r'\d+', '', text)
        text = re.sub(r'\s+[a-z]\s+', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        
        tokens = text.split()
        
        stop_words = set(stopwords.words('english'))
        tokens = [word for word in tokens if word not in stop_words]
        
        lemmatizer = WordNetLemmatizer()
        tokens = [lemmatizer.lemmatize(word) for word in tokens]
        
        return ' '.join(tokens)
    except Exception as e:
        print(f"Error processing text: {text}. Error: {e}")
        return ""

def load_models():
    """Load all the model components"""
    print("Loading models...")
    
    # Load the main model and vectorizer
    detector.model = joblib.load('random_forest_model.joblib')
    detector.tfidf = joblib.load('tfidf_vectorizer.joblib')
    
    # Load the URL extractor
    with open('url_extractor.pkl', 'rb') as f:
        detector.url_extractor = pickle.load(f)
    
    # Load the semantic analyzer config
    with open('semantic_analyzer_config.pkl', 'rb') as f:
        detector.semantic_analyzer_config = pickle.load(f)
    
    # Initialize BERT and Sentence Transformer models
    print("Loading BERT and SentenceTransformer models...")
    detector.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    detector.bert_model = BertModel.from_pretrained('bert-base-uncased')
    detector.sentence_model = SentenceTransformer('all-mpnet-base-v2')
    
    print("All models loaded successfully")

class SemanticAnalyzer:
    def __init__(self, config):
        self.known_phishing_phrases = config['known_phishing_phrases']
        self.negative_tone_words = config['negative_tone_words']
        self.overly_positive_words = config['overly_positive_words']
        
        # Initialize embeddings for known phishing phrases
        self.phishing_embeddings = detector.sentence_model.encode(self.known_phishing_phrases)
    
    def analyze_tone(self, text):
        negative_score = sum(text.lower().count(word) for word in self.negative_tone_words)
        positive_score = sum(text.lower().count(word) for word in self.overly_positive_words)
        
        if negative_score >= 2 and positive_score == 0:
            return "negative/urgent"
        elif positive_score >= 2 and negative_score == 0:
            return "overly_positive"
        elif positive_score >= 1 and negative_score >= 1:
            return "mixed_emotional_manipulation"
        else:
            return "neutral"
    
    def detect_generic_greeting(self, text):
        first_sentence = text.split('.')[0].lower() if '.' in text else text.lower()
        generic_greetings = ['dear customer', 'dear sir/madam', 'valued customer', 'dear account holder', 'dear member', 'dear user', 'dear client', 'dear winner', 'attention customer', 'account notification', 'service notification', 'important notice', 'security alert', 'dear friend', 'dear valued one', 'dear email user', 'dear account owner', 'dear webmail user', 'dear mail user', 'dear subscriber']
        return any(greet in first_sentence for greet in generic_greetings)
    
    def analyze_semantics(self, text):
        inputs = detector.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = detector.bert_model(**inputs)
        bert_embedding = outputs.last_hidden_state.mean(dim=1).numpy()
        
        text_embedding = detector.sentence_model.encode([text])
        similarities = cosine_similarity(text_embedding, self.phishing_embeddings)
        max_similarity = np.max(similarities)
        avg_similarity = np.mean(similarities)
        
        tone = self.analyze_tone(text)
        generic_greeting = self.detect_generic_greeting(text)
        
        blob = TextBlob(text)
        spelling_errors = len(blob.correct().split()) - len(blob.split())
        
        contextual_anomaly = self.detect_contextual_anomalies(text)
        
        return {
            'bert_embedding': bert_embedding,
            'max_phishing_similarity': max_similarity,
            'avg_phishing_similarity': avg_similarity,
            'tone': tone,
            'generic_greeting': generic_greeting,
            'spelling_errors': spelling_errors,
            'contextual_anomalies': contextual_anomaly,
            'is_semantically_suspicious': (
                max_similarity > 0.75 or 
                avg_similarity > 0.55 or
                tone in ["negative/urgent", "overly_positive", "mixed_emotional_manipulation"] or
                generic_greeting or
                spelling_errors >= 2 or
                contextual_anomaly
            )
        }
    
    def detect_contextual_anomalies(self, text):
        common_brands = ['paypal', 'bank', 'amazon', 'ebay', 'apple', 'microsoft', 'netflix', 'spotify', 'irs', 'tax', 'dhl', 'fedex', 'ups']
        brand_in_text = any(brand in text.lower() for brand in common_brands)
        suspicious_context = any(word in text.lower() for word in ['click', 'verify', 'update', 'confirm'])
        return brand_in_text and suspicious_context

def predict_message(message):
    """Predict if a message is phishing with detailed explanations"""
    if not detector.model:
        raise ValueError("Models not loaded")
    
    # Initialize semantic analyzer
    semantic_analyzer = SemanticAnalyzer(detector.semantic_analyzer_config)
    
    # Preprocess text
    processed_text = preprocess_text(message)
    
    # Extract features
    features = {}
    
    # 1. Traditional features
    features['urgent_count'] = sum(message.lower().count(word) for word in URGENT_WORDS)
    features['too_good_count'] = sum(message.lower().count(word) for word in TOO_GOOD_WORDS)
    features['request_count'] = sum(message.lower().count(word) for word in REQUEST_WORDS)
    features['message_length'] = len(message)
    features['special_chars'] = len(re.findall(r'[^\w\s]', message))
    features['caps_words'] = len(re.findall(r'\b[A-Z]{2,}\b', message))
    features['phone_numbers'] = len(re.findall(r'[\+\(]?[0-9][0-9\-\(\)]{8,}[0-9]', message))
    
    # URL features
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
    features['has_url'] = int(len(urls) > 0)
    
    url_suspicion_scores = []
    url_predictions = []
    
    for url in urls:
        url_feat = detector.url_extractor.extract_url_features(url)
        prediction = detector.url_extractor.predict_url(url_feat)
        url_predictions.append(prediction)
        url_suspicion_scores.append(prediction['probability'])
    
    features['max_url_suspicion'] = max(url_suspicion_scores) if url_suspicion_scores else 0
    features['avg_url_suspicion'] = np.mean(url_suspicion_scores) if url_suspicion_scores else 0
    features['phishing_url_count'] = sum(1 for pred in url_predictions if pred['prediction'] == 1)
    
    # 2. Semantic features
    semantic_features = semantic_analyzer.analyze_semantics(message)
    
    features['max_phishing_similarity'] = semantic_features['max_phishing_similarity']
    features['avg_phishing_similarity'] = semantic_features['avg_phishing_similarity']
    features['tone_negative'] = int(semantic_features['tone'] == "negative/urgent")
    features['tone_positive'] = int(semantic_features['tone'] == "overly_positive")
    features['tone_mixed'] = int(semantic_features['tone'] == "mixed_emotional_manipulation")
    features['generic_greeting'] = int(semantic_features['generic_greeting'])
    features['spelling_errors'] = semantic_features['spelling_errors']
    features['contextual_anomaly'] = int(semantic_features['contextual_anomalies'])
    
    features_df = pd.DataFrame([features])
    
    # Create TF-IDF features
    tfidf_features = detector.tfidf.transform([processed_text])
    tfidf_df = pd.DataFrame(tfidf_features.toarray(), columns=detector.tfidf.get_feature_names_out())
    
    # Combine features
    X = pd.concat([features_df.reset_index(drop=True), tfidf_df.reset_index(drop=True)], axis=1)
    
    # Predict
    probability = detector.model.predict_proba(X)[0][1]
    is_phishing = probability > 0.5
    
    return {
        'is_phishing': bool(is_phishing),
        'probability': float(probability),
        'features': features,
        'url_predictions': url_predictions,
        'semantic_features': semantic_features
    }

# API Endpoints
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'No message provided'}), 400
    
    try:
        result = predict_message(data['message'])
        return jsonify({
            'status': 'success',
            'result': {
                'is_phishing': result['is_phishing'],
                'probability': result['probability'],
                'features': result['features'],
                'url_predictions': result['url_predictions'],
                'semantic_features': result['semantic_features']
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    load_models()
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))