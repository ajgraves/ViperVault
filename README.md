# ViperVault
ViperVault is a python-based CGI web script that allows you to securely view log and command output from your server.

## Configuration Options
In the `unified_config.json` file, the following configuration options are available

### Example File
```json
{
  "password": "YOUR SECRET PASSWORD HERE",
  "refresh_interval": 30,
  "session_duration": 86400,
  "inactivity_timeout": 3600,
  "log_views": {
    "Test 1": "echo test 1",
    "Test 2": {
      "cmd": "tech test 2",
      "refresh": 15
    }
  }
}
```

Let's break down the example file for the options

### `password`
This option sets the password used to access your interface. Set it wisely.

### `refresh_interval`
This is the default refresh interval for the auto refresh feature. The default is 30 seconds, and is reasonable. Some logs you may want to refresh more frequently (say, 10 seconds). Others you may not wish to refresh at all. You can configure those settings in the `log_views` section.

### `session_duration`
This is the length of time your session cookie is valid for.

### `inactivity_timeout`
This is the length of time at which your session will time out if you leave it inactive.

### `log_views`
This section is where you define each entry you want to be available in the application. It has the following available settings:
- `cmd`: The command to execute, whose output will be shared.
- `refresh`: This is the refresh interval, in seconds. The default is set through `refresh_interval` defined earlier in the configuration. If the default is fine, you don't need to specify one here. If you don't want the log to auto refresh, set this to `0` or `-1`.
- `bottom`: This is a boolean (true/false) that indicates if the newest output is at the bottom (`true`, default) or top (`false`). The output will automatically scroll to the top or bottom, depending on how this option is set.
- `safe_output`: This is a boolean (true/false) that indicates of the log output should be escaped/sanitized (`true`, default) or output directly (`false`, and potentially dangerous). **WARNING: Setting this as false could potentially introduce cross-site scripting (XSS) or other vulnerabilities if the log output contains malicious content. Mitigations are employed to prevent malicious content from running, even in cases where we set `safe_output` to `false`, but the possibility still exists.**
