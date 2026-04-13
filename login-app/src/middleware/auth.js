// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.redirect('/login');
}

// Middleware to redirect if already logged in
function isGuest(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect('/home');
  }
  return next();
}

module.exports = { isAuthenticated, isGuest };
