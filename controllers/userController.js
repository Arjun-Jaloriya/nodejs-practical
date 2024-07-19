const User = require("../model/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const {
  registerValidate,
  loginValidate,
  changePasswordValidate,
} = require("../validation/userValidation");

const redirectRegisterpage = (req, res) => {
  const { status, msg } = req.query;
  res.render("register", { errors: {}, status, msg });
};

const redirectLoginpage = (req, res) => {
  const { status, msg } = req.query;
  res.render("login", { errors: {}, status, msg });
};

const redirectChangePassword = (req, res) => {
    const { status, msg } = req.query;
  res.render("changePassword", { errors: {},status, msg  });
};
const register = async (req, res) => {
  try {
    const { error } = registerValidate.validate(req.body, {
      abortEarly: false,
    });
    if (error) {
      const errors = error.details.reduce((acc, err) => {
        acc[err.context.key] = err.message;
        return acc;
      }, {});
      return res.render("register", { errors, status: null, msg: null });
    }

    const { userName, email, password } = req.body;
    const existigUser = await User.findOne({ email: email });
    if (existigUser) {
      res.redirect("/user/register?status=400msg=user allready registred");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = new User({
      userName: userName,
      email: email,
      password: hashedPassword,
    });
    await userData.save();

    res.redirect("/user/login?status=200&msg=Registration successful");
  } catch (error) {
    console.log(error);
    res.redirect("/user/register?status=500&msg=Something went wrong");
  }
};

const login = async (req, res) => {
  try {
    const { error, value } = loginValidate.validate(req.body, {
      abortEarly: false,
    });
    if (error) {
      const errors = error.details.reduce((acc, err) => {
        acc[err.context.key] = err.message;
        return acc;
      }, {});
      return res.render("login", { errors, status: null, msg: null });
    }

    const { email, password } = value;
    let user = await User.findOne({ email: email });

    if (!user) {
      return res.redirect("/user/login?status=401&msg=User Not Registered");
    }

    const matchPassword = await bcrypt.compare(password, user.password);

    if (!matchPassword) {
      return res.redirect("/user/login?status=401&msg=Invalid credentials");
    }
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/user/dashboard?status=200&msg=Login successful");
  } catch (error) {
    console.log(error);
    res.redirect("/user/login?status=500&msg=Something went wrong");
  }
};

const redirectDashboard = async (req, res) => {
    try {
        const user = req.user;
        const { status, msg } = req.query;
        res.render('dashboard', { user, status, msg, errors: {} });
      } catch (err) {
        console.error(err);
        res.redirect('/user/login?status=500&msg=Something went wrong');
      }
};

const changePassword = async (req, res) => {
  try {
    const { error } = changePasswordValidate.validate(req.body, {
      abortEarly: false,
    });
    if (error) {
      const errors = error.details.reduce((acc, err) => {
        acc[err.context.key] = err.message;
        return acc;
      }, {});
      const user = await User.findById(req.user._id);
      return res.render('changePassword', { user, status: null, msg: null, errors });
    }
    const { oldPassword, newPassword, confirmPassword } = req.body;

    const user = await User.findById(req.user._id);

    const validPassword = await bcrypt.compare(oldPassword, user.password);
    if (!validPassword) {
      const errors = { oldPassword: "Invalid old password" };
      return res.render('changePassword', { user, status: null, msg: null, errors });
    }

    if (newPassword !== confirmPassword) {
      const errors = { confirmPassword: "Passwords do not match" };
      return res.render("changePassword", { user, status: null, msg: null,errors });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.redirect('/user/dashboard?status=200&msg=Password changed successfully');
  } catch (error) {
    console.log(error);
    res.redirect('/user/dashboard?status=500&msg=Something went wrong');
  }
};

const logout = (req, res) => {
  res.clearCookie("token");
  res.redirect('/user/login');
};

module.exports = {
  redirectRegisterpage,
  redirectLoginpage,
  register,
  login,
  redirectDashboard,
  changePassword,
  redirectChangePassword,
  logout,
};
