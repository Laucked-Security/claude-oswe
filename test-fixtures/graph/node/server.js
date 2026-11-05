// SP10 graph fixture (node): Express app that mounts the users router behind an auth middleware.
const users = require('./routes/users');

function ensureAuthenticated(req, res, next) {
  next();
}

app.use('/users', ensureAuthenticated, users);
app.get('/health', (req, res) => res.send('ok'));
