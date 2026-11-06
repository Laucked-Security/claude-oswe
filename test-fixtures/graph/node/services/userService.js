// SP10 graph fixture (node): `this.exec` dispatch is ambiguous because AdminService overrides exec.
const child_process = require('child_process');

class UserService {
  run(id, cmd) {
    this.exec(cmd);
  }

  exec(c) {
    child_process.exec(c); /* VULN */
  }
}

class AdminService extends UserService {
  exec(c) {}
}

module.exports = { UserService, AdminService };
