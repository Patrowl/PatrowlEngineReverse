# 🚀 Engine Development

**Steps to build a new engine:** `your_engine`


## 🛠️ Setup Folder & Environment

Follow these steps to get started:

1. **Copy & Rename Template**  
   - Duplicate the `engine_template` folder and rename it:
     ```bash
     cp -R engine_template your_engine
     cd your_engine
     ```
2. **Set Up Python Environment**  
   - Create and activate a virtual environment:
     ```bash
     python3.10 -m venv env
     source env/bin/activate
     ```
3. **Install Dependencies**  
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```

> **Note:** This ensures you have an isolated environment for your engine development.


## 🔧 Define Options & Metadata

### 🎛️ Options

When you start a scan, you can specify various options for the engine. These options are defined in `metadatas.py` within the `Options` class. Specifying each option's type helps the engine validate inputs and enforce proper typing.

- **Example:**  
  If your engine should accept assets (each asset being an object like `{datatype: str, value: str}`), add the following attribute to `Options`:
  ```python
  assets: List[Asset]
  ```

- **Define the Asset Class:**  
  Create the class to define the asset structure:
  ```python
  class Asset(BaseModel):
      datatype: str
      value: str
  ```
  
> 💡 *Tip:* Check out the owl DNS example for further guidance on implementing these options.


### 📜 Metadata

Metadata consists of engine parameters such as API tokens and paths to binaries. They are defined in the `metadatas.json` file.

- **To add new metadata (e.g., `secret_api_token`):**
  1. **Update `metadatas.json`:**  
     Add the new metadata entry:
     ```json
     "secret_api_token": "SECRET_VALUE"
     ```
  2. **Sync with Template:**  
     Also, include it in the `metadatas.json.sample` file without the secret value (this file is pushed on github).
  3. **Define in Code:**  
     Add the type definition for the metadata in `metadata.py` to ensure proper data validation and typing.


## 🔍 Testing Engine

### 🧪 Basics Testing

When developing your engine, you can create unit tests to ensure everything works as expected.

- **Unit Test Class:**  
  Your test class should extend the `TestEngine` class. This allows you to execute the `start_scan` method as if the scan were initiated in a real life environment.

- **How It Works:**  
  The `start_scan` method accepts options as parameters and returns a list of results

> Check the sample test file in the `tests` folder to see an example.


### 🤖 Advanced Mocking

For scenarios where your engine interacts with external services (e.g., websites or APIs), it's crucial to ensure consistent test results.

- **Why Mock?**  
  Mocking allows you to simulate responses from external requests, ensuring that your tests always receive predictable data.

- **How To Do It:**  
  Use patching to override methods such as `requests.get` so that they return a custom object with your desired test data.


> Check the OwlDNS unit test for a detailed example on implementing mocking.

