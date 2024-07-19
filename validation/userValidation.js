const Joi = require("joi");

const registerValidate = Joi.object({
  userName: Joi.string().required().messages({
    "any.required": "UserName is required",
  }),
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().min(6).required().messages({
    "string.min": "Password must be at least 6 characters long",
    "any.required": "Password is required",
  }),
  confirmPassword: Joi.any().valid(Joi.ref('password')).required().messages({
    'any.only': 'Passwords do not match',
    'any.required': 'Confirm Password is required',
  }),
});

const loginValidate = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Invalid Email Format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
});

const changePasswordValidate = Joi.object({
    oldPassword: Joi.string().required().messages({
        'any.required': 'Old Password is required',
      }),
      newPassword: Joi.string().min(6).required().messages({
        'string.min': 'New Password must be at least 6 characters long',
        'any.required': 'New Password is required',
      }),
      confirmPassword: Joi.any().valid(Joi.ref('newPassword')).required().messages({
        'any.only': 'Passwords do not match',
        'any.required': 'Confirm Password is required',
      }),
});
module.exports = { registerValidate, loginValidate, changePasswordValidate };
