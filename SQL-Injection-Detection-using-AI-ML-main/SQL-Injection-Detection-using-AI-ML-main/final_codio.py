from flask import Flask, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import logging
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from joblib import dump, load
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/mini'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'reddyshanmuka67@gmail.com' 
app.config['MAIL_PASSWORD'] = 'yool qjhi dvve edqv'
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']


db = SQLAlchemy(app)
mail = Mail(app)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

block_handler = logging.FileHandler('blocked_ips.log')
block_handler.setLevel(logging.WARNING)
block_handler.setFormatter(logging.Formatter('%(asctime)s - BLOCKED - %(message)s'))
logger.addHandler(block_handler)

if os.path.isfile('classifier.joblib'):
    print("Loading existing model.")
    clf = load('classifier.joblib')
    vectorizer = load('vectorizer.joblib')
    with open(r"data.txt", 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    texts, labels = [], []
    for line in data:
        temp = line.split(",")
        text = temp[0]
        label = temp[1]
        if label in ['0', '1']:
            texts.append(text)
            labels.append(label)
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    vectorizer2 = TfidfVectorizer(max_df=0.85, stop_words='english')
    text_vectorized = vectorizer2.fit_transform(X_train)
else:
    print("Training new model.")
    with open(r"data.txt", 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    texts, labels = [], []
    for line in data:
        temp = line.split(",")
        text = temp[0]
        label = temp[1]
        if label in ['0', '1']:
            texts.append(text)
            labels.append(label)

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    vectorizer = TfidfVectorizer(max_df=0.85, stop_words='english')
    X_train_vectorized = vectorizer.fit_transform(X_train)
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train_vectorized, y_train)

    X_test_vectorized = vectorizer.transform(X_test)
    y_pred = clf.predict(X_test_vectorized)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy}")
    dump(clf, 'classifier.joblib')
    dump(vectorizer, 'vectorizer.joblib')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.name


def send_alert_email(user_email):
    """Send an email to alert the user to change their password."""
    msg = Message('Security Alert: Suspicious Activity Detected',
                  recipients=[user_email])
    msg.body = "Dear User,\n\nYour recent request has been blocked due to suspicious activity. Please change your password to ensure your account's security.\n\nBest regards,\nYour Security Team"
    with app.app_context():
        mail.send(msg)


@app.route('/', methods=['GET', 'POST'])
def index():
    global vectorizer
    if request.method == 'POST':
        user_input = request.form['user_input']
        password = request.form['password']
        user_email = request.form.get('email')  # Assuming you have an email field in your form

        query = str(user_input + password)
        query_vector = vectorizer.transform([query]) 
        is_malicious = clf.predict(query_vector)  
        if is_malicious == ['1']:
            logger.error(f"Blocked request from IP {request.remote_addr} to URL {request.url}: {query}")
            with open('blocked_ips.log', 'a') as f:
                f.write(request.remote_addr + '\n')
            send_alert_email(user_email)  
            return "Request Blocked"
        
        print("Valid request")
        cosine_similarities = cosine_similarity(query_vector, text_vectorized).flatten()
        most_similar_query_index = cosine_similarities.argsort()[-1]
        similarity_score = cosine_similarities[most_similar_query_index]
        if similarity_score >= 0.6:
            logger.error(f"Blocked request from IP {request.remote_addr} to URL {request.url}: {query}")
            with open('blocked_ips.log', 'a') as f:
                f.write(request.remote_addr + '\n')
            send_alert_email(user_email)  
            similarity_percentage = round(similarity_score * 100, 2)
            return f"Request Blocked. Query similarity percentage: {similarity_percentage}%"
        else:
            similarity_percentage = round(similarity_score * 100, 2)
            return f"Request successfully processed. Query similarity percentage: {similarity_percentage}%"

    return '''
    <html>
<head>
  <title>SQL Injection Detection and Prevention Using Artificial Intelligence</title>
  <style>
    body {
      background: url(https://rare-gallery.com/uploads/posts/1012591-hacking-hackers-darkness-black-and-white-monochrome-photography.jpg) no-repeat center center fixed;
      background-size: cover;
      background-position: center;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      font-family: 'Arial', sans-serif;
      color: white;
    }
    
    .container {
      background: rgba(0, 0, 0, 0.7);
      padding: 30px;
      border-radius: 15px;
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
      max-width: 400px;
      width: 100%;
      text-align: center;
    }

    h1 {
      font-size: 2em;
      margin: 0;
      color: yellow;
    }
    
    h2 {
      font-size: 1.5em;
      margin: 10px 0;
      color: #e5e5e5;
    }

    .form-group {
      margin-bottom: 15px;
      text-align: left;
    }
    
    label {
      display: block;
      margin-bottom: 5px;
      font-weight: bold;
      color: #ddd;
    }
    
    input {
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
      transition: all 0.3s;
    }

    input:focus {
      outline: none;
      box-shadow: 0 0 5px #ffcc00;
    }

    button {
      background: linear-gradient(90deg, #333, #555);
      color: #fff;
      padding: 12px 24px;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      cursor: pointer;
      transition: background 0.3s, transform 0.3s;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
    }

    button:hover {
      background: linear-gradient(90deg, #555, #777);
      transform: translateY(-2px);
    }

    .alert {
      margin-top: 20px;
      padding: 10px;
      background-color: #f44336;
      color: #fff;
      font-weight: bold;
      border-radius: 5px;
      display: none; /* Hide by default */
    }

    .success {
      background-color: #008000;
    }
    
    .danger {
      background-color: #f44336;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>SQL Injection Detection</h1>
    <h2>Submit your data</h2>
    <form method="post">
      <div class="form-group">
        <label for="user_input">User Input:</label>
        <input type="text" name="user_input" required>
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" name="password" required>
      </div>
      <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" name="email" required>
      </div>
      <button type="submit">Submit</button>
    </form>
    <div class="alert" id="alert"></div>
  </div>
  <script>
    const alertBox = document.getElementById('alert');

    // Function to show alert message
    function showAlert(message, isSuccess) {
      alertBox.textContent = message;
      alertBox.className = isSuccess ? 'alert success' : 'alert danger';
      alertBox.style.display = 'block';
    }
  </script>
</body>
</html>
    '''


if __name__ == '__main__':
    app.run(debug=True)
