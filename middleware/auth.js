const jwt = require("jsonwebtoken");
const User = require("../model/userModel");

const isAuthenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect("/user/login?status=401&msg=Please login first");

    const verifyuser = jwt.verify(token, process.env.JWT_SECRET);
    if (!verifyuser) {
      return res.redirect("/user/login?status=403&msg=Access denied");
    }
    req.user = await User.findOne({ _id: verifyuser._id });
    if (!req.user) return res.redirect('/user/login?status=404&msg=User not found');
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.redirect("/user/login?status=401&msg=Token has expired");
    }
    console.error(error);
    return res.redirect("/user/login?status=500&msg=Something went wrong");
  }
};

module.exports = isAuthenticate;
