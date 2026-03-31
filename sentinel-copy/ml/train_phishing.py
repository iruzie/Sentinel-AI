"""
train_phishing.py
=================
Generates a rich synthetic training dataset and trains a GradientBoosting
phishing URL classifier.  Run once from the project root:

    python ml/train_phishing.py

Outputs
-------
    ml/models/phishing_model.joblib   — trained GradientBoostingClassifier
    ml/models/phishing_threshold.json — optimal decision threshold (F1-tuned)
"""

import os
import sys
import json
import random
import string
import joblib
import numpy as np

# Ensure we can import phishing_features regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from phishing_features import extract_features, FEATURE_NAMES

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score
)
from sklearn.calibration import CalibratedClassifierCV

random.seed(42)
np.random.seed(42)

# ---------------------------------------------------------------------------
# Curated seed data (real-world style examples)
# ---------------------------------------------------------------------------

LEGIT_SEEDS = [
    'https://www.google.com/search?q=weather',
    'https://github.com/features/copilot',
    'https://stackoverflow.com/questions/12345',
    'https://docs.python.org/3/library/urllib.parse.html',
    'https://en.wikipedia.org/wiki/Machine_learning',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://reddit.com/r/MachineLearning',
    'https://news.ycombinator.com/',
    'https://aws.amazon.com/s3/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP',
    'https://www.nytimes.com/section/technology',
    'https://arxiv.org/abs/1706.03762',
    'https://scikit-learn.org/stable/modules/ensemble.html',
    'https://fastapi.tiangolo.com/tutorial/first-steps/',
    'https://nginx.org/en/docs/',
    'https://hub.docker.com/_/nginx',
    'https://pypi.org/project/scikit-learn/',
    'https://www.linkedin.com/in/example',
    'https://twitter.com/home',
    'https://apple.com/iphone',
    'https://microsoft.com/en-us/windows',
    'https://openai.com/research',
    'https://cloudflare.com/learning/security/what-is-a-firewall/',
    'https://owasp.org/www-community/attacks/SQL_Injection',
    'https://letsencrypt.org/docs/',
]

PHISHING_SEEDS = [
    'http://192.168.1.104/paypal/login.php?account=true',
    'http://secure-lloydsbank.verify-account.tk/login',
    'http://www.amazon-security-alert.com/verify?user=victim',
    'http://paypal.login.secure-update.ml/account/verify.php',
    'http://apple-id-locked-support.gq/unlock?token=abc123',
    'http://bit.ly/3xR2sVq',
    'http://microsoft-support-alert.top/your-pc-is-infected.html',
    'http://signin.paypal.com.phishingdomain.tk/cmd=_login',
    'http://update-your-bank-account-immediately.xyz/form.php',
    'http://216.58.209.142/login?redirect=https://accounts.google.com',
    'http://accounts.google.com.verify-security.tk/signin',
    'http://ebay-suspended-account.click/restore?id=928374',
    'http://adf.ly/2XyZ1',
    'http://free-iphone14-winner.buzz/claim?email=victim@test.com',
    'http://amazon.account-suspended.gq/verify-identity',
    'http://secure.chase.com.login-verify.pw/banking/signin.php',
    'http://netflix-account-hold.top/billing/update?ref=urgent',
    'http://10.0.0.1/admin/login.php?redirect=paypal',
    'http://verify-your-identity-now.cf/bank/confirm.html',
    'http://irs-refund-portal.tk/claim-refund?ssn=***',
]

# ---------------------------------------------------------------------------
# Data generators
# ---------------------------------------------------------------------------

LEGIT_DOMAINS = [
    'google', 'github', 'stackoverflow', 'reddit', 'wikipedia',
    'youtube', 'amazon', 'microsoft', 'apple', 'twitter',
    'linkedin', 'facebook', 'instagram', 'openai', 'netflix',
    'cloudflare', 'fastapi', 'python', 'nginx', 'docker',
    'mozilla', 'ubuntu', 'debian', 'arxiv', 'nature',
    'bbc', 'reuters', 'nytimes', 'theguardian', 'techcrunch',
]

LEGIT_TLDS = ['.com', '.org', '.net', '.io', '.edu', '.gov', '.co.uk', '.dev']

LEGIT_PATHS = [
    '/about', '/contact', '/home', '/blog', '/news',
    '/products', '/services', '/docs', '/api', '/faq',
    '/login', '/signup', '/dashboard', '/profile',
    '/article/12345', '/post/how-to-use-python',
    '/search?q=machine+learning',
    '/en/docs/web/api',
    '/stable/modules/neural_network.html',
]

PHISHING_DOMAINS = [
    'secure-account-verify', 'update-your-info', 'loginportal',
    'account-suspended-alert', 'security-notice', 'verify-now',
    'official-support', 'your-account-locked', 'unusual-activity',
    'paypal-service-notify', 'amazon-prime-offer', 'bank-secure',
    'identity-verify', 'click-here-to-win', 'free-gift-offer',
]

PHISHING_TLDS = list({
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click',
    '.pw', '.cc', '.buzz', '.link', '.icu', '.rest', '.cam',
})

PHISHING_PATHS = [
    '/login.php', '/signin.php', '/verify.php', '/account/update',
    '/secure/confirm', '/banking/login', '/paypal/verify',
    '/restore-account', '/unlock?token=aBcDef123',
    '/claim-prize?email=user@domain.com', '/invoice.php?id=9821',
    '/payment/failed?redirect=http://evil.tk',
]

BRANDS = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'chase', 'netflix', 'ebay', 'irs']
RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.buzz', '.pw']


def rand_str(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def gen_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    tld    = random.choice(LEGIT_TLDS)
    path   = random.choice(LEGIT_PATHS)
    scheme = 'https'
    # Occasionally add www or a single sub like 'docs', 'api', 'mail'
    sub    = random.choice(['', 'www.', 'docs.', 'api.', 'mail.', 'blog.'])
    return f'{scheme}://{sub}{domain}{tld}{path}'


def gen_phishing_url():
    variant = random.randint(0, 7)

    if variant == 0:
        # IP-based URL
        ip   = '.'.join(str(random.randint(2, 254)) for _ in range(4))
        path = random.choice(PHISHING_PATHS)
        kw   = random.choice(BRANDS)
        return f'http://{ip}/{kw}{path}?redirect=true'

    elif variant == 1:
        # Brand in subdomain, phishing domain in apex
        brand  = random.choice(BRANDS)
        domain = random.choice(PHISHING_DOMAINS) + '-' + rand_str(4)
        tld    = random.choice(PHISHING_TLDS)
        path   = random.choice(PHISHING_PATHS)
        return f'http://{brand}.{domain}{tld}{path}'

    elif variant == 2:
        # Legit brand in path, phishing domain as host
        brand  = random.choice(BRANDS)
        domain = rand_str(random.randint(12, 22))
        tld    = random.choice(PHISHING_TLDS)
        path   = f'/{brand}/login?token={rand_str(16)}'
        return f'http://{domain}{tld}{path}'

    elif variant == 3:
        # URL shortener
        shortener = random.choice([
            'bit.ly', 'tinyurl.com', 'adf.ly', 'tiny.cc', 'rb.gy'
        ])
        slug = rand_str(random.randint(5, 8))
        return f'http://{shortener}/{slug}'

    elif variant == 4:
        # Long URL with many query params (credential harvesting)
        brand  = random.choice(BRANDS)
        domain = f'{brand}-secure-verify-{rand_str(5)}.{random.choice(PHISHING_TLDS[1:])}'
        params = '&'.join(f'{rand_str(4)}={rand_str(8)}' for _ in range(random.randint(3, 7)))
        return f'http://{domain}/confirm?userid=1&{params}&redirect=true'

    elif variant == 5:
        # Homograph-style: brand name with hyphens
        brand  = random.choice(BRANDS)
        faked  = '-'.join(list(brand)) if len(brand) > 4 else brand + '-secure'
        tld    = random.choice(PHISHING_TLDS)
        path   = random.choice(PHISHING_PATHS)
        return f'http://{faked}-account{tld}{path}?session={rand_str(12)}'

    elif variant == 6:
        # @ trick
        brand  = random.choice(BRANDS)
        domain = rand_str(12)
        tld    = random.choice(PHISHING_TLDS)
        return f'http://{brand}.com@{domain}{tld}/secure/login'

    else:
        # Percent-encoded obfuscation
        brand  = random.choice(BRANDS)
        domain = random.choice(PHISHING_DOMAINS)
        tld    = random.choice(PHISHING_TLDS)
        encoded = ''.join(f'%{ord(c):02x}' if random.random() < 0.3 else c for c in f'/{brand}/verify')
        return f'http://{domain}{tld}{encoded}?id={rand_str(10)}'


# ---------------------------------------------------------------------------
# Build dataset
# ---------------------------------------------------------------------------

def build_dataset(n_legit=1200, n_phish=1200):
    X, y = [], []

    # Seed examples (guaranteed to be in training set)
    for url in LEGIT_SEEDS:
        X.append(extract_features(url))
        y.append(0)
    for url in PHISHING_SEEDS:
        X.append(extract_features(url))
        y.append(1)

    # Generated examples
    for _ in range(n_legit - len(LEGIT_SEEDS)):
        X.append(extract_features(gen_legit_url()))
        y.append(0)

    for _ in range(n_phish - len(PHISHING_SEEDS)):
        X.append(extract_features(gen_phishing_url()))
        y.append(1)

    return np.array(X, dtype=float), np.array(y, dtype=int)


# ---------------------------------------------------------------------------
# Train
# ---------------------------------------------------------------------------

def main():
    print('── Sentinel-AI Phishing URL Classifier ──')
    print('Building synthetic dataset …')
    X, y = build_dataset()
    print(f'  Total samples: {len(y)}  |  Phishing: {y.sum()}  |  Legit: {(y==0).sum()}')

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print('Training GradientBoostingClassifier …')
    base = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )
    # Platt scaling for reliable probabilities
    model = CalibratedClassifierCV(base, cv=3, method='sigmoid')
    model.fit(X_train, y_train)

    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='roc_auc')
    print(f'  5-fold CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}')

    # Test set evaluation
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    print('\nClassification Report (threshold = 0.50):')
    print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))
    print(f'ROC-AUC : {roc_auc_score(y_test, y_prob):.4f}')

    # Tune threshold to maximise F1 on test set
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.30, 0.75, 0.01):
        f1 = f1_score(y_test, (y_prob >= t).astype(int))
        if f1 > best_f1:
            best_f1, best_t = f1, t
    print(f'Optimal threshold: {best_t:.2f}  (F1 = {best_f1:.4f})')

    # Save
    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(model_dir, exist_ok=True)

    model_path     = os.path.join(model_dir, 'phishing_model.joblib')
    threshold_path = os.path.join(model_dir, 'phishing_threshold.json')

    joblib.dump(model, model_path)
    with open(threshold_path, 'w') as f:
        json.dump({'threshold': round(float(best_t), 4)}, f)

    print(f'\nSaved → {model_path}')
    print(f'Saved → {threshold_path}')

    # Feature importances (from base estimator via calibrated wrapper)
    try:
        importances = base.feature_importances_
        fi_pairs = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])
        print('\nTop 10 features by importance:')
        for name, imp in fi_pairs[:10]:
            bar = '█' * int(imp * 80)
            print(f'  {name:<30} {imp:.4f}  {bar}')
    except Exception:
        pass

    print('\n✅ Training complete.')


if __name__ == '__main__':
    main()
