// SP10 graph fixture (node): a router whose handler reaches UserService through a `new` binding.
const { UserService } = require('../services/userService');

const svc = new UserService();

function run(req, res) {
  svc.run(req.params.id, req.body.cmd);
}

router.post('/:id/run', run);

function cb() {}

// the parameter `cb` shadows the top-level function `cb`
function helper(cb) {
  cb();
}

module.exports = router;
