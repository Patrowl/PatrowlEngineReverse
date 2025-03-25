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
  If your engine should accept assets (and each asset being an object like `{datatype: str, value: str}`), add the following attribute to `Options`:
  ```python
  class Options(BaseModel):
      ...
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

## 🛠️ Development

Begin developing your engine by defining two methods in your `TemplateEngine` class (which you can rename to your engine's name):


### ⚙️ load_config

This method is **optional** and is called when the engine starts, receiving the engine metadata as its parameter. Use it to initialize components like your API client.

- **Example Usage:**
  ```python
  def load_config(self, metadatas):
      # Initialize your API client with secret metadata
      self.api_client = lib.api_client(metadatas.secret_api_token)
  ```
- **Tip:**  
  Once set up, you can access your API client later in the code via `self.api_client`.


### 🚀 start_scan

This method is called when the engine receives a scan request. It retrieves the options provided and initiates the scanning process. The results returned from this method are directly pushed into the datalake.

### Return Options

You must return either:

- **A list of issues:**
  ```python
  return [{"issue": "test 1"}, {"issue": "test 2"}]
  ```

- **A generator (yield one or several issues):**
  ```python
  issues = [{"issue": "test 1"}, {"issue": "test 2"}]
  for issue in issues:
      yield issue
  ```

> **Pro Tip:**  
> Using a yield is often better because it immediately inserts each issue into the database. This means that if the engine crashes (e.g., due to a server shutdown), you won't lose the issues that have already been processed.


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

### ▶ Running Tests

<!-- > Usefull [VSCode Extension](https://marketplace.visualstudio.com/items?itemName=LittleFoxTeam.vscode-python-test-adapter) to easily run your tests -->

#### 🚀 Run All Tests

To execute all test cases in the `tests` folder, use:

```bash
python -m unittest discover tests -p "*_test.py"
```

#### 🎯 Run a Specific Test

If you want to run a single test, for example, `test_do_dns_transfer()` from `tests/dns_test.py`, use:

```bash
python -m unittest tests.dns_test.TestEngine.test_do_dns_transfer
```

> 💡 **Tip:** Running specific tests is useful when debugging a particular function without executing the entire test suite.


## *WIP* PRODUCTION Environement testing

To test engine like it's gonna be used in production, you need to:

- Setup rabbitmq
```
docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:4.0-management
```

Go to http://127.0.0.1:15672, `guest/guest` to visualize queues
- Add some test tasks in rabbitMQ
  - Check `task_add.py` for OwlDNS example

- Start your engine with `python engine.py` (in your python env & engine folder)

Engine should consume the tasks