const { Schema, model } = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

userSchema.methods.validatePassword = function (rawPassword) {
  const hashedPassword = this.password;
  return bcrypt.compare(rawPassword, hashedPassword);
};

userSchema.statics.hashPassword = function (rawPassword) {
  return bcrypt.hash(rawPassword, 12);
};

module.exports = model('user', userSchema);
