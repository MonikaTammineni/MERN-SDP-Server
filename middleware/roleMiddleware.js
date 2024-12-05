const isAdmin = (req, res, next) => {
    if (req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ message: 'Access Denied: Admins Only' });
    }
  };
  
  const isDoctor = (req, res, next) => {
    if (req.user.role === 'doctor') {
      next();
    } else {
      res.status(403).json({ message: 'Access Denied: Doctors Only' });
    }
  };
  
  module.exports = { isAdmin, isDoctor };
  