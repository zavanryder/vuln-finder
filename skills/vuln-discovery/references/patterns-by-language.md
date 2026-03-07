# Patterns by Language

Sinks, dangerous APIs, and pattern hints per language for each bug class. Search for these (and trace data flow from user input) when analyzing code.

---

## Table of contents

1. [Java](#java)
2. [Python](#python)
3. [Go](#go)
4. [C# (.NET)](#c-net)
5. [PHP](#php)
6. [Ruby](#ruby)
7. [JavaScript](#javascript)
8. [TypeScript](#typescript)

---

## Java

- **deserialization**: `ObjectInputStream.readObject`, `XMLDecoder.readObject`, `Yaml.load` (SnakeYAML), `ObjectMapper.readValue` with polymorphic types, `XStream.fromXML`, any custom `readObject`/`readResolve`.
- **sql-injection**: String concatenation/interpolation with `Statement.execute*`, `PreparedStatement` built from concatenated SQL; `JdbcTemplate` with concatenated query strings; ORM raw SQL with concatenation.
- **nosql-injection**: MongoDB `BasicDBObject`/`Document` built from user string; `Criteria` with raw user input in keys/values.
- **command-injection**: `Runtime.getRuntime().exec(String)`, `ProcessBuilder` with string command/args from input, `ScriptEngine` with user script.
- **path-traversal**: `new File(userPath)`, `Paths.get(userPath)`, `FileInputStream`/`FileOutputStream` with user path, `Resource` resolution from request.
- **ssrf**: `URL.openConnection()`, `HttpClient`/`HttpURLConnection` with user URL, `ImageIO.read(url)`, `Request.Get(userUrl)`.
- **xss**: Writing request params to JSP/HTML without encoding; `PrintWriter`/response with unescaped user data; template engines (Thymeleaf, Freemarker) with unescaped input.
- **xxe**: `DocumentBuilderFactory` without `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING)` and external entities disabled; `SAXParser`, `XMLReader`, `Transformer` with external DTD/entities; `XMLInputFactory` without secure settings.
- **ldap-injection**: `LdapTemplate.search` with filter built from user input; `SearchControls` with user-controlled attributes; concatenated filter strings.
- **ssti**: Freemarker, Velocity, Thymeleaf with user-controlled template strings or expression parts.
- **hardcoded-secrets**: Literal passwords, `SecretKeySpec`, API keys in properties/source; default credentials.
- **weak-crypto**: `Random` for tokens/secrets; `MD5`/`SHA1` for passwords; `DES`, `RC4`; ECB mode.
- **mass-assignment**: DTOs/entities bound from request without field allowlist; setters for roles/permissions exposed.
- **auth-bypass**: Missing `@PreAuthorize`/security checks; comparing roles as strings from request; path-based access without authorization.

---

## Python

- **deserialization**: `pickle.loads`, `yaml.load` (unsafe loader), `marshal.loads`, `json.loads` on untrusted with custom `object_hook` that constructs objects.
- **sql-injection**: Raw SQL with `%` or `.format()` or f-strings; `execute(sql % params)`; ORM `.raw()` or `extra()` with user in SQL string.
- **nosql-injection**: Building MongoDB queries from user dict/string (e.g. `{"$where": user_input}`); `eval` in query.
- **command-injection**: `os.system`, `subprocess.call`/`run`/`Popen` with `shell=True` and user in command string; `eval`/`exec` on user input.
- **path-traversal**: `open(user_path)`, `os.path.join` with user segment, `Path(user_path)`, file send with user filename.
- **ssrf**: `requests.get(user_url)`, `urllib.request.urlopen(user_url)`, `httpx.get`, `aiohttp` with user URL.
- **xss**: Rendering user input in Jinja2/Flask/Django templates without `| e` or `autoescape`; returning user data in JSON/HTML without encoding.
- **xxe**: `lxml.etree.fromstring`, `xml.etree.ElementTree` with default parser; `defusedxml` not used for untrusted XML.
- **ssti**: Jinja2/Mako/Tornado templates with user-controlled template string or variable name (e.g. `Template(user_input).render()`).
- **hardcoded-secrets**: Passwords/keys in source, env defaults in code, `config.py` with secrets.
- **weak-crypto**: `random` module for tokens; `hashlib.md5`/`sha1` for passwords; weak or default crypto.
- **mass-assignment**: Pydantic/attrs/dict unpacking from request without allowlist; setting internal attributes from request.
- **auth-bypass**: Missing `@login_required` or permission checks; trusting session/header without verification.

---

## Go

- **deserialization**: `gob.Decode`, `encoding/json` into `interface{}` then type assertion to executable types; custom unmarshaling that runs code.
- **sql-injection**: `db.Exec`/`Query` with Sprintf or concatenation; raw SQL with user input.
- **nosql-injection**: Building bson/query from user-supplied map or string.
- **command-injection**: `exec.Command` with user in command or args (especially when joined into one string for shell); `os/exec` with unsanitized input.
- **path-traversal**: `os.Open(userPath)`, `filepath.Join` with user segment, serving files by user-supplied filename.
- **ssrf**: `http.Get(userURL)`, `http.Client` with user URL, `net.Dial` with user host.
- **xss**: Template execution (html/template, text/template) with user content without escaping; writing user data to response.
- **hardcoded-secrets**: String literals for API keys, passwords; keys in config files in repo.
- **weak-crypto**: `math/rand` for secrets; weak hashes or default crypto.
- **auth-bypass**: Handlers without auth middleware; trusting client-supplied user/role.

---

## C# (.NET)

- **deserialization**: `BinaryFormatter.Deserialize`, `ObjectStateFormatter.Deserialize`, `NetDataContractSerializer`, `XmlSerializer` on untrusted with dangerous types; `YamlDotNet` unsafe load; `Newtonsoft.Json` with `TypeNameHandling` and user-controlled type.
- **sql-injection**: Concatenation into `SqlCommand.CommandText`; `FromSqlRaw` with string format and user input.
- **nosql-injection**: MongoDB driver with filter built from user string or unchecked BSON.
- **command-injection**: `Process.Start` with user in filename/arguments; script execution with user input.
- **path-traversal**: `File.Open(userPath)`, `Path.Combine` with user segment, `new FileStream(userPath)`.
- **ssrf**: `HttpClient.GetAsync(userUrl)`, `WebRequest.Create(userUrl)`, `HttpClient` with user-supplied URI.
- **xss**: Razor/views with `@Html.Raw(userInput)`; response write of unencoded user data.
- **xxe**: `XmlDocument.Load`, `XmlReader.Create` without secure settings; `DtdProcessing` not prohibited.
- **ldap-injection**: `DirectorySearcher` with filter string from user; concatenated LDAP filter.
- **ssti**: Razor or other template engine with user-controlled template content.
- **hardcoded-secrets**: Connection strings, API keys in config/source; secrets in code.
- **weak-crypto**: `Random` for crypto; weak algorithms; default keys.
- **mass-assignment**: Model binding from request without `[BindNever]` or allowlist; binding to sensitive properties.
- **auth-bypass**: Missing `[Authorize]` or policy checks; trusting claims from untrusted source.

---

## PHP

- **deserialization**: `unserialize($userInput)`, `phar://` with user path (phar deserialization).
- **sql-injection**: Concatenation into `mysqli_query`, `mysql_query`, `PDO::query`; raw SQL in Laravel `DB::select($sql)` with user in string.
- **nosql-injection**: MongoDB queries built from `$_GET`/`$_POST` without validation.
- **command-injection**: `exec`, `shell_exec`, `system`, `passthru`, `popen`, backticks, `proc_open` with user input.
- **path-traversal**: `include`/`require` with user path; `file_get_contents(userPath)`; `readfile`, `fopen` with user path.
- **ssrf**: `file_get_contents($url)`, `fopen($url)`, `curl_exec` with user URL, `SoapClient` with user WSDL.
- **xss**: `echo $_GET['x']`, `print` without encoding; Twig/Blade with `|raw` or unescaped user data.
- **xxe**: `simplexml_load_string`, `DOMDocument::loadXML` with default options; external entities enabled.
- **ldap-injection**: `ldap_search` with filter built from user input.
- **ssti**: Twig/Blade/Smarty with user-controlled template string or variable-name injection.
- **hardcoded-secrets**: Passwords in config; API keys in source; `putenv` with secrets.
- **weak-crypto**: `rand()`/`mt_rand()` for tokens; `md5`/`sha1` for passwords.
- **mass-assignment**: Eloquent/Model `fill($request->all())` without `$fillable` or allowlist.
- **auth-bypass**: Missing auth middleware; comparing session/input without proper verification.

---

## Ruby

- **deserialization**: `YAML.load` (unsafe), `YAML.unsafe_load`, `Marshal.load`, `Marshal.restore`; `Oj.load` with mode allowing object creation; `Psych.load` on untrusted input.
- **sql-injection**: String interpolation in `execute`, `query`, `find_by_sql`; `where` with raw SQL string and user input; ActiveRecord `order`/`reorder`/`select` with params; concatenation into raw SQL.
- **nosql-injection**: MongoDB driver (MongoID, Moped) with user-supplied query hash or `$where` string; building criteria from params without sanitization.
- **command-injection**: `system(user_input)`, `exec`, backticks, `Kernel.exec`, `Open3.capture2`/`popen3` with user in command string; `IO.popen` with user input.
- **path-traversal**: `File.read(params[:path])`, `File.open`, `File.new`, `Pathname.new` with user path; `send_file`/`send_data` with user-controlled filename or path; `Rails.root.join` with user segment.
- **ssrf**: `open(user_url)` (Kernel#open), `URI.open`, `Net::HTTP.get(URI(user_url))`, `RestClient.get(user_url)`, `Faraday.get`, `HTTParty.get` with user URL; `Curly.get`/HTTP gem with user-controlled URI.
- **xss**: `raw`, `html_safe`, `<%= user_input %>` without escaping in ERB; `content_tag`/`tag` with user content; `render inline:` with user string; disabling `html_escape` or using `safe_join` with unescaped data.
- **xxe**: `Nokogiri::XML` with default options; `REXML::Document` parsing untrusted XML without disabling external entities; `LibXML::XML::Document` with unsafe options.
- **ldap-injection**: Net::LDAP filter built from user string; concatenated filter or DN.
- **ssti**: `ERB.new(user_input).result`, `eval` in template context; user-controlled template string in Slim/Haml/Liquid; `render inline: params[:template]`.
- **open-redirect**: `redirect_to params[:url]`, `redirect_to request.referer` without allowlist; `redirect_to` with user-controlled host/path.
- **hardcoded-secrets**: Secrets in `config/`, `credentials`, env files in repo; literal API keys or passwords in source; `Rails.application.secrets` with defaults in code.
- **weak-crypto**: `Random.rand` for tokens; `Digest::MD5`/`SHA1` for passwords; weak or default cipher options.
- **mass-assignment**: `Model.new(params)` or `update(params)` without `permit`; `assign_attributes(params)`; strong params missing or overly permissive.
- **insecure-file-upload**: Uploaded file saved with original filename or user path; no type/size validation; stored in web-accessible directory.
- **auth-bypass**: `skip_before_action :authenticate_user!`; missing `before_action` for auth; trusting `params[:user_id]` or session without verification; `current_user` checks missing or bypassable.

---

## JavaScript

- **prototype-pollution**: Assignment to `__proto__`, `constructor.prototype`; `Object.assign`, `merge`, `extend` with user object; parsing JSON and merging into existing object; `lodash.merge` with user input.
- **sql-injection**: Raw SQL with template literals or concatenation (e.g. in `pg.query`, `mysql.query`); user in query string.
- **nosql-injection**: MongoDB `find`/`findOne` with user object; `$where` with user string; building query from request body.
- **command-injection**: `child_process.exec`/`execSync` with user in command string; `spawn` with shell and user in args.
- **path-traversal**: `fs.readFile(userPath)`, `path.join` with user segment; serving files by user-supplied name.
- **ssrf**: `fetch(userUrl)`, `axios.get(userUrl)`, `http.get(userUrl)`, `request(userUrl)`.
- **xss**: `innerHTML = userInput`, `document.write`, `eval(userInput)`; template literals in HTML; unescaped data in React (dangerouslySetInnerHTML) or similar.
- **open-redirect**: `res.redirect(req.query.url)`, `window.location = userInput`; redirect URL from query/body without allowlist.
- **hardcoded-secrets**: API keys, tokens in source or env files in repo.
- **weak-crypto**: `Math.random()` for tokens; weak or deprecated crypto usage.
- **auth-bypass**: Routes without auth middleware; trusting cookie/header without verification.

---

## TypeScript

Same as JavaScript (Node/Deno/browser). Additional attention:

- **prototype-pollution**: Typed merge/extend with `any` or unchecked user input; same sinks as JS.
- **sql-injection**: TypeORM `query()` with string + params; raw queries with template literals.
- **nosql-injection**: Mongoose with user object in `find`/`where`; `$where` with user string.
- **xss**: Same as JS; Angular sanitization bypass; Vue/React unescaped output.
- **ssrf**: Same as JS; server-side `fetch`/axios with user URL.

Use the same sink lists as JavaScript for command-injection, path-traversal, open-redirect, hardcoded-secrets, weak-crypto, auth-bypass.
