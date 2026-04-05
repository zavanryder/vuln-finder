# Web and Injection Patterns by Language

Sinks, dangerous APIs, and pattern hints for injection, XSS, SSRF, deserialization, secrets, crypto, file upload, path traversal, and general web vulnerabilities. Search for these and trace data flow from user input.

---

## Table of contents

1. [Java](#java)
2. [Python](#python)
3. [Go](#go)
4. [C# (.NET)](#c-net)
5. [PHP](#php)
6. [Ruby](#ruby)
7. [JavaScript / TypeScript](#javascript--typescript)
8. [Kotlin](#kotlin)

---

## Java

- **deserialization**: `ObjectInputStream.readObject`, `XMLDecoder.readObject`, `Yaml.load` (SnakeYAML), `ObjectMapper.readValue` with polymorphic types (`@JsonTypeInfo`), `XStream.fromXML`, any custom `readObject`/`readResolve`.
- **sql-injection**: String concatenation/interpolation with `Statement.execute*`, `PreparedStatement` built from concatenated SQL; `JdbcTemplate` with concatenated query strings; ORM raw SQL with concatenation; Spring Data `@Query` with SpEL and user input.
- **nosql-injection**: MongoDB `BasicDBObject`/`Document` built from user string; `Criteria` with raw user input in keys/values.
- **command-injection**: `Runtime.getRuntime().exec(String)`, `ProcessBuilder` with string command/args from input, `ScriptEngine` with user script.
- **code-injection**: `ScriptEngine.eval(userInput)`, `MethodHandle`/reflection with user-controlled class/method names, `Expression` evaluation with user input.
- **path-traversal**: `new File(userPath)`, `Paths.get(userPath)`, `FileInputStream`/`FileOutputStream` with user path, `Resource` resolution from request. **Zip Slip**: `ZipEntry.getName()` used in `new File()` without path validation during archive extraction.
- **ssrf**: `URL.openConnection()`, `HttpClient`/`HttpURLConnection` with user URL, `ImageIO.read(url)`, `Request.Get(userUrl)`, `RestTemplate` with user URL.
- **xss**: Writing request params to JSP/HTML without encoding; `PrintWriter`/response with unescaped user data; template engines (Thymeleaf `th:utext`, Freemarker) with unescaped input.
- **xxe**: `DocumentBuilderFactory` without `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING)` and external entities disabled; `SAXParser`, `XMLReader`, `Transformer` with external DTD/entities; `XMLInputFactory` without secure settings.
- **ldap-injection**: `LdapTemplate.search` with filter built from user input; `SearchControls` with user-controlled attributes; concatenated filter strings.
- **ssti**: Freemarker, Velocity, Thymeleaf with user-controlled template strings or expression parts.
- **hardcoded-secrets**: Literal passwords, `SecretKeySpec`, API keys in properties/source; default credentials.
- **weak-crypto**: `Random` (not `SecureRandom`) for tokens/secrets; `MD5`/`SHA1` for passwords; `DES`, `RC4`; ECB mode.
- **insecure-file-upload**: Uploaded file stored with original filename without sanitization; MIME type trusted from client; no size limit; stored in web-accessible path.
- **open-redirect**: `response.sendRedirect(userParam)`, Spring `redirect:` with user-controlled URL.
- **sensitive-data-exposure**: `e.printStackTrace()` in response, verbose error pages in production, logging request bodies with credentials, `@ToString` on entities with sensitive fields.

---

## Python

- **deserialization**: `pickle.loads`, `yaml.load` (unsafe loader), `marshal.loads`, `json.loads` on untrusted with custom `object_hook` that constructs objects, `shelve.open` on untrusted files.
- **sql-injection**: Raw SQL with `%` or `.format()` or f-strings; `execute(sql % params)`; ORM `.raw()` or `extra()` with user in SQL string; SQLAlchemy `text()` with string formatting.
- **nosql-injection**: Building MongoDB queries from user dict/string (e.g. `{"$where": user_input}`); `eval` in query.
- **command-injection**: `os.system`, `subprocess.call`/`run`/`Popen` with `shell=True` and user in command string; `eval`/`exec` on user input.
- **code-injection**: `eval(user_input)`, `exec(user_input)`, `compile()` with user code, `importlib` with user-controlled module name.
- **path-traversal**: `open(user_path)`, `os.path.join` with user segment (does not prevent absolute path override), `Path(user_path)`, file send with user filename. **Zip Slip**: `zipfile.extractall()` or manual extraction without checking `..` in member names; `tarfile.extractall()` without `filter` parameter (Python 3.12+).
- **ssrf**: `requests.get(user_url)`, `urllib.request.urlopen(user_url)`, `httpx.get`, `aiohttp` with user URL. Partial SSRF: user controls path/query but not host, yet can redirect via 302.
- **xss**: Rendering user input in Jinja2/Flask/Django templates without `| e` or `autoescape`; returning user data in JSON/HTML without encoding; `Markup(user_input)` in Flask; `mark_safe(user_input)` in Django.
- **xxe**: `lxml.etree.fromstring`, `xml.etree.ElementTree` with default parser; `defusedxml` not used for untrusted XML.
- **ssti**: Jinja2/Mako/Tornado templates with user-controlled template string (e.g. `Template(user_input).render()`); `render_template_string(user_input)` in Flask.
- **hardcoded-secrets**: Passwords/keys in source, env defaults in code, `config.py` with secrets, Django `SECRET_KEY` in settings.
- **weak-crypto**: `random` module for tokens (not `secrets`); `hashlib.md5`/`sha1` for passwords; weak or default crypto.
- **insecure-file-upload**: Uploaded file saved with `filename` from request without sanitization; no type/size validation; `werkzeug.utils.secure_filename` not used.
- **open-redirect**: `redirect(request.args.get('next'))` without URL validation; Flask/Django redirect with user-controlled target.
- **sensitive-data-exposure**: `DEBUG = True` in production Django; `traceback` in API responses; logging passwords or tokens.

---

## Go

- **deserialization**: `gob.Decode`, `encoding/json` into `interface{}` then type assertion to executable types; custom unmarshaling that runs code; `yaml.Unmarshal` on untrusted input.
- **sql-injection**: `db.Exec`/`Query` with `Sprintf` or concatenation; raw SQL with user input not using `$1` placeholders.
- **nosql-injection**: Building bson/query from user-supplied map or string.
- **command-injection**: `exec.Command` with user in command or args (especially when joined into one string for shell); `os/exec` with unsanitized input.
- **code-injection**: `plugin.Open` with user-controlled path; template execution with user-controlled template string in `text/template`.
- **path-traversal**: `os.Open(userPath)`, `filepath.Join` with user segment, serving files by user-supplied filename. **Zip Slip**: `archive/zip` or `archive/tar` extraction without validating that extracted paths stay within target directory.
- **ssrf**: `http.Get(userURL)`, `http.Client` with user URL, `net.Dial` with user host.
- **xss**: `text/template` (no auto-escaping) with user content; writing user data to `http.ResponseWriter` without escaping; `html/template` is safe by default but `template.HTML()` type conversion bypasses escaping.
- **xxe**: Go's `encoding/xml` does not process external entities by default, but third-party XML libraries may.
- **hardcoded-secrets**: String literals for API keys, passwords; keys in config files in repo.
- **weak-crypto**: `math/rand` for secrets (not `crypto/rand`); weak hashes or default crypto.
- **insecure-file-upload**: Uploaded file saved with client-provided filename; no content-type or size validation; `io.Copy` without size limit.
- **open-redirect**: `http.Redirect` with user-controlled URL; `r.URL.Query().Get("redirect")` passed to redirect.
- **sensitive-data-exposure**: Verbose error messages with `fmt.Fprintf(w, err.Error())`; debug endpoints left enabled.

---

## C# (.NET)

- **deserialization**: `BinaryFormatter.Deserialize`, `ObjectStateFormatter.Deserialize`, `NetDataContractSerializer`, `XmlSerializer` on untrusted with dangerous types; `YamlDotNet` unsafe load; `Newtonsoft.Json` with `TypeNameHandling` and user-controlled type.
- **sql-injection**: Concatenation into `SqlCommand.CommandText`; `FromSqlRaw` with string format and user input; `ExecuteSqlRaw` with interpolation.
- **nosql-injection**: MongoDB driver with filter built from user string or unchecked BSON.
- **command-injection**: `Process.Start` with user in filename/arguments; script execution with user input.
- **code-injection**: `CSharpCodeProvider.CompileAssemblyFromSource` with user code; Roslyn scripting with user input.
- **path-traversal**: `File.Open(userPath)`, `Path.Combine` with user segment (does not prevent absolute path override), `new FileStream(userPath)`.
- **ssrf**: `HttpClient.GetAsync(userUrl)`, `WebRequest.Create(userUrl)`, `HttpClient` with user-supplied URI.
- **xss**: Razor/views with `@Html.Raw(userInput)`; response write of unencoded user data.
- **xxe**: `XmlDocument.Load`, `XmlReader.Create` without secure settings; `DtdProcessing` not prohibited.
- **ldap-injection**: `DirectorySearcher` with filter string from user; concatenated LDAP filter.
- **ssti**: Razor or other template engine with user-controlled template content.
- **hardcoded-secrets**: Connection strings, API keys in config/source; secrets in code.
- **weak-crypto**: `Random` for crypto (not `RandomNumberGenerator`); weak algorithms; default keys.
- **insecure-file-upload**: `IFormFile` saved with `FileName` from request; no validation; stored in wwwroot.
- **open-redirect**: `Redirect(userParam)` without `Url.IsLocalUrl()` check.
- **sensitive-data-exposure**: `UseDeveloperExceptionPage()` in production; connection strings in error responses.

---

## PHP

- **deserialization**: `unserialize($userInput)`, `phar://` with user path (phar deserialization).
- **sql-injection**: Concatenation into `mysqli_query`, `mysql_query`, `PDO::query`; raw SQL in Laravel `DB::select($sql)` with user in string.
- **nosql-injection**: MongoDB queries built from `$_GET`/`$_POST` without validation.
- **command-injection**: `exec`, `shell_exec`, `system`, `passthru`, `popen`, backticks, `proc_open` with user input.
- **code-injection**: `eval($userInput)`, `assert($userInput)` (PHP < 8.0), `preg_replace` with `/e` modifier, `create_function`.
- **path-traversal**: `include`/`require` with user path; `file_get_contents(userPath)`; `readfile`, `fopen` with user path.
- **ssrf**: `file_get_contents($url)`, `fopen($url)`, `curl_exec` with user URL, `SoapClient` with user WSDL.
- **xss**: `echo $_GET['x']`, `print` without encoding; Twig/Blade with `|raw` or unescaped user data; `{!! $var !!}` in Blade.
- **xxe**: `simplexml_load_string`, `DOMDocument::loadXML` with default options; external entities enabled.
- **ldap-injection**: `ldap_search` with filter built from user input.
- **ssti**: Twig/Blade/Smarty with user-controlled template string or variable-name injection.
- **hardcoded-secrets**: Passwords in config; API keys in source; `putenv` with secrets.
- **weak-crypto**: `rand()`/`mt_rand()` for tokens; `md5`/`sha1` for passwords.
- **insecure-file-upload**: `$_FILES['file']['name']` used directly; no type/size validation; `move_uploaded_file` to web-accessible directory.
- **open-redirect**: `header("Location: " . $_GET['url'])` without validation.
- **sensitive-data-exposure**: `display_errors = On` in production; `phpinfo()` accessible; stack traces in responses.

---

## Ruby

- **deserialization**: `YAML.load` (unsafe), `YAML.unsafe_load`, `Marshal.load`, `Marshal.restore`; `Oj.load` with mode allowing object creation; `Psych.load` on untrusted input.
- **sql-injection**: String interpolation in `execute`, `query`, `find_by_sql`; `where` with raw SQL string and user input; ActiveRecord `order`/`reorder`/`select` with params; concatenation into raw SQL.
- **nosql-injection**: MongoDB driver (MongoID, Moped) with user-supplied query hash or `$where` string.
- **command-injection**: `system(user_input)`, `exec`, backticks, `Kernel.exec`, `Open3.capture2`/`popen3` with user in command string; `IO.popen` with user input.
- **code-injection**: `eval(user_input)`, `instance_eval`, `class_eval`, `send(user_input)`, `public_send` with user-controlled method name.
- **path-traversal**: `File.read(params[:path])`, `File.open`, `File.new`, `Pathname.new` with user path; `send_file`/`send_data` with user-controlled filename; `Rails.root.join` with user segment.
- **ssrf**: `open(user_url)` (Kernel#open), `URI.open`, `Net::HTTP.get(URI(user_url))`, `RestClient.get(user_url)`, `Faraday.get`, `HTTParty.get` with user URL.
- **xss**: `raw`, `html_safe`, `<%= user_input %>` without escaping in ERB; `content_tag`/`tag` with user content; `render inline:` with user string.
- **xxe**: `Nokogiri::XML` with default options; `REXML::Document` parsing untrusted XML without disabling external entities.
- **ldap-injection**: Net::LDAP filter built from user string; concatenated filter or DN.
- **ssti**: `ERB.new(user_input).result`, `eval` in template context; `render inline: params[:template]`.
- **open-redirect**: `redirect_to params[:url]`, `redirect_to request.referer` without allowlist.
- **hardcoded-secrets**: Secrets in `config/`, `credentials`, env files in repo; literal API keys or passwords in source.
- **weak-crypto**: `Random.rand` for tokens; `Digest::MD5`/`SHA1` for passwords; weak cipher options.
- **insecure-file-upload**: Uploaded file saved with original filename; no type/size validation; stored in public directory.
- **sensitive-data-exposure**: `config.consider_all_requests_local = true` in production; detailed error pages; logging params with passwords (missing `filter_parameters`).

---

## JavaScript / TypeScript

Patterns apply to both JS and TS. For TypeScript, also watch for `any` types that bypass type-safety in merge/assign operations.

- **prototype-pollution**: Assignment to `__proto__`, `constructor.prototype`; `Object.assign`, `merge`, `extend` with user object; `lodash.merge`/`defaultsDeep` with user input; `deep-extend`, `deepen`, `deepmerge` without `__proto__` guard; parsing JSON and merging into existing object.
- **deserialization**: `node-serialize`/`serialize-javascript` with `eval` on untrusted; `js-yaml.load` with unsafe schema; `vm2` sandbox escape patterns.
- **sql-injection**: Raw SQL with template literals or concatenation (e.g. in `pg.query`, `mysql.query`, `knex.raw`); user in query string; TypeORM `query()` with string + params.
- **nosql-injection**: MongoDB `find`/`findOne` with user object; `$where` with user string; Mongoose with user object in `find`/`where`.
- **command-injection**: `child_process.exec`/`execSync` with user in command string; `spawn` with shell and user in args.
- **code-injection**: `eval(userInput)`, `new Function(userInput)`, `vm.runInNewContext(userInput)`, `setTimeout`/`setInterval` with string argument.
- **path-traversal**: `fs.readFile(userPath)`, `path.join` with user segment (does not prevent absolute path); serving files by user-supplied name. **Zip Slip**: `adm-zip`, `unzipper`, `tar` extraction without validating entry paths.
- **ssrf**: `fetch(userUrl)`, `axios.get(userUrl)`, `http.get(userUrl)`, `got(userUrl)`, `node-fetch` with user URL.
- **xss**: `innerHTML = userInput`, `document.write`, `eval(userInput)`; `dangerouslySetInnerHTML` in React; unescaped data in Angular (`[innerHTML]` binding bypassing sanitizer); Vue `v-html` with user data.
- **open-redirect**: `res.redirect(req.query.url)`, `window.location = userInput`; redirect URL from query/body without allowlist.
- **hardcoded-secrets**: API keys, tokens in source or `.env` files committed to repo; secrets in `package.json` scripts.
- **weak-crypto**: `Math.random()` for tokens/secrets; `crypto.createHash('md5')` for passwords.
- **insecure-file-upload**: `multer` without `fileFilter` or `limits`; uploaded file saved with `originalname`; no content validation.
- **sensitive-data-exposure**: `stack` property in error responses; `NODE_ENV !== 'production'` debug paths; console.log of tokens/passwords.

### Electron (desktop apps)

When `package.json` lists `electron`, audit the main process and preload scripts as a separate trust boundary from renderer code:

- **electron-rce**: `nodeIntegration: true` (renderer can `require('child_process')`); `contextIsolation: false` (prototype pollution leaks main-world to isolated-world); `sandbox: false` combined with either.
- **electron-shell**: `shell.openExternal(userUrl)` with non-`https?:` schemes -- `file://`, `smb://`, and custom protocol handlers can execute local binaries.
- **electron-ipc**: `ipcMain.handle` / `ipcMain.on` reachable from renderer without `event.senderFrame.url` validation -- any iframe (including ad/3rd-party content) can invoke privileged handlers.
- **electron-preload**: `contextBridge.exposeInMainWorld` exposing `fs`, `child_process`, or unfiltered IPC pass-through; the preload script *is* the trust boundary, so audit what it forwards.
- **electron-navigation**: `will-navigate` / `new-window` handlers without an allowlist; `<webview>` with `allowpopups` or no `preload` restriction.

---

## Kotlin

Kotlin shares most sinks with Java. Additional or Kotlin-specific patterns:

- **deserialization**: `kotlinx.serialization` with polymorphic types and user-controlled class discriminator; same Java sinks apply.
- **sql-injection**: `JdbcTemplate` with string templates; Exposed framework raw SQL with user interpolation; Spring Data `@Query` with SpEL.
- **command-injection**: `Runtime.getRuntime().exec()`, `ProcessBuilder`, Kotlin `Process` extensions with user input.
- **code-injection**: `javax.script.ScriptEngine` with user input; Kotlin scripting API with user code.
- **path-traversal**: Same as Java. Kotlin extensions like `File(userPath).readText()`.
- **ssrf**: Same as Java. Ktor client with user-controlled URL; `ktorClient.get(userUrl)`.
- **xss**: Same as Java. Kotlin/JS with `innerHTML`.
- **hardcoded-secrets**: `const val API_KEY = "..."` in companion objects; `application.conf` with plaintext secrets.
- **sensitive-data-exposure**: `data class` with `toString()` exposing sensitive fields.
