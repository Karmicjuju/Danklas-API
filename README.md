# Danklas-API

## FastAPI Project Setup

### 1. Create and Activate Virtual Environment
```
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```
pip install fastapi uvicorn
```

### 3. Run the FastAPI App
```
uvicorn app.main:app --reload
```

Visit [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser to see the default FastAPI welcome message.

### 4. Project Structure
```
Danklas-API/
├── app/
│   └── main.py
├── venv/
└── README.md
``` 