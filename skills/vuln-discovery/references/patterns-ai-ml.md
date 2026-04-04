# AI/ML Pipeline Patterns

Patterns for model integrity, unsafe deserialization of ML artifacts, prompt injection, and RAG pipeline security.

---

## Table of contents

1. [ML model integrity](#ml-model-integrity)
2. [Prompt injection](#prompt-injection)
3. [General search strategy](#general-search-strategy)

---

## ML model integrity

Loading serialized ML models or evaluation artifacts from untrusted sources without integrity verification. Many ML serialization formats (pickle, torch, joblib) can execute arbitrary code on load.

### Dangerous patterns (Python)

**Unsafe model loading:**
```python
# VULNERABLE: pickle-based formats execute arbitrary code on load
import torch
model = torch.load("model.pt")                # uses pickle internally
model = torch.load(user_path)                  # user-controlled path + pickle

import joblib
model = joblib.load("model.pkl")               # pickle-based

import pickle
data = pickle.loads(uploaded_bytes)             # direct pickle

from sklearn.externals import joblib
clf = joblib.load(open("classifier.pkl", "rb")) # sklearn via pickle
```

**No integrity check before loading:**
```python
# VULNERABLE: model downloaded and loaded without hash/signature verification
response = requests.get(model_url)
with open("model.pt", "wb") as f:
    f.write(response.content)
model = torch.load("model.pt")  # no checksum, no signature
```

**Eval/report artifacts loaded unsafely:**
```python
# VULNERABLE: evaluation reports or metrics loaded via pickle
with open("eval_results.pkl", "rb") as f:
    results = pickle.load(f)  # attacker-controlled eval artifact -> RCE
```

### Safe alternatives
```python
# SAFER: torch with weights_only=True (PyTorch 2.0+)
model = torch.load("model.pt", weights_only=True)

# SAFER: safetensors format (no code execution)
from safetensors.torch import load_file
tensors = load_file("model.safetensors")

# SAFER: ONNX (declarative graph, no arbitrary code)
import onnxruntime
session = onnxruntime.InferenceSession("model.onnx")

# SAFER: verify checksum before loading
import hashlib
expected = "sha256:abc123..."
actual = hashlib.sha256(open("model.pt", "rb").read()).hexdigest()
assert actual == expected.split(":")[1]
```

### Dangerous patterns (JavaScript/TypeScript)
```javascript
// VULNERABLE: loading TensorFlow.js model from user-controlled URL
const model = await tf.loadLayersModel(userUrl);

// VULNERABLE: ONNX model from untrusted source
const session = await ort.InferenceSession.create(userPath);
```

### Dangerous patterns (Java)
```java
// VULNERABLE: DL4J model via Java serialization
ModelSerializer.restoreMultiLayerNetwork(new File(userPath));

// VULNERABLE: PMML model from untrusted source
new PMMLModel(new FileInputStream(userPath));
```

### What to check
- Any `torch.load`, `pickle.load`, `joblib.load` call: is the source trusted? Is there a checksum?
- Model download + load sequences: is there integrity verification between download and load?
- Whether the project uses `safetensors`, ONNX, or `weights_only=True` as safe defaults.
- Eval artifacts and training metadata: same deserialization risk as models themselves.

---

## Prompt injection

User-supplied input concatenated into LLM prompts or RAG context without sanitization, allowing the user to override system instructions or extract sensitive data.

### Dangerous patterns (Python)

**Direct prompt concatenation:**
```python
# VULNERABLE: user input in system/assistant prompt
prompt = f"You are a helpful assistant. User query: {user_input}"
response = client.chat.completions.create(messages=[{"role": "user", "content": prompt}])

# VULNERABLE: user input as template variable in prompt
template = "Analyze this document: {document}\nQuestion: {question}"
prompt = template.format(document=uploaded_text, question=user_query)
```

**RAG context injection:**
```python
# VULNERABLE: retrieved documents injected without sanitization
context = "\n".join([doc.page_content for doc in retriever.get_relevant_documents(query)])
prompt = f"Based on this context:\n{context}\n\nAnswer: {query}"
# If an attacker controls a document in the vector store, they can inject instructions
```

**Tool/function calling injection:**
```python
# VULNERABLE: user input flows into tool descriptions or function args
tools = [{"name": "search", "description": f"Search for {user_input}"}]

# VULNERABLE: database query results used as context without sanitization
rows = db.execute("SELECT content FROM docs WHERE topic = ?", (topic,))
context = "\n".join(row[0] for row in rows)
# Stored injection: malicious content in DB rows becomes part of the prompt
```

### Dangerous patterns (JavaScript/TypeScript)
```javascript
// VULNERABLE: template literal with user input in prompt
const prompt = `You are an assistant. Context: ${userInput}. Answer the question.`;

// VULNERABLE: RAG pipeline without sanitization
const docs = await vectorStore.similaritySearch(query);
const context = docs.map(d => d.pageContent).join('\n');
const prompt = `Context: ${context}\n\nQuestion: ${query}`;
```

### Dangerous patterns (Java)
```java
// VULNERABLE: string concatenation in LLM prompt
String prompt = "Analyze: " + userInput + "\nProvide summary.";
```

### What to check
- User input or retrieved content concatenated into prompt strings.
- Whether prompt construction uses any input sanitization or output parsing that strips injection attempts.
- RAG pipelines: can an attacker control documents in the vector store (via uploads, shared databases, web scraping)?
- Tool/function calling: can user input influence tool names, descriptions, or argument schemas?
- Second-order injection: data from databases, files, or APIs that flows into prompts -- the original data source may be attacker-controlled.

---

## General search strategy

### High-signal grep patterns for ML model integrity
```
torch\.load|joblib\.load|pickle\.load|pickle\.loads
dill\.load|cloudpickle\.load|shelve\.open
ModelSerializer\.restore|PMMLModel
weights_only|safetensors
tf\.loadLayersModel|InferenceSession
```

### High-signal grep patterns for prompt injection
```
f"|f'.*\{.*input|\.format\(.*input|\.format\(.*query
completions\.create|ChatCompletion|chat\.completions
langchain|LLMChain|RetrievalQA|ConversationalRetrievalChain
get_relevant_documents|similarity_search|vectorstore
openai\.chat|anthropic\.messages|client\.chat
prompt.*=.*f"|template.*format.*user|context.*=.*join
```

### Analysis approach
1. **Find model loading calls** (`torch.load`, `pickle.load`, `joblib.load`) and trace the file/path source. Is it user-controlled or downloaded without verification?
2. **Find LLM API calls** and trace prompt construction backward. Does user input flow in without sanitization?
3. **Find RAG retrieval** (`similarity_search`, `get_relevant_documents`) and check whether retrieved content is sanitized before prompt inclusion.
4. **Check for integrity verification** (checksums, signatures) between model download and load.
5. **Check for safe alternatives**: `weights_only=True`, `safetensors`, ONNX instead of pickle-based formats.
