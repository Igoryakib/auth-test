const { User } = require("../models");
const jwt = require("../utils/jwt");

exports.register = async (req, res, next) => {
  try {
    // 1. Створіть нового користувача з унікальним username та зашифрованим паролем
    // 2. Підготуйте payload для генерації jwt токена
    // 3. Згенеруйте jwt токен
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      res.status(409).send("This user already exists");
      return;
    }
    const hashedPassword = await User.hashPassword(password);

    const user = await User.create({
      username,
      password: hashedPassword,
    });

    const payload = {
      _id: user._id,
    };

    const token = jwt.generate(payload);
    res.json({
      message: 'User successfully registered',
      user,
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
};

exports.login = async (req, res, next) => {
  try {
    // 1. Виконайте валідацію полей username, password
    // 2. Підготуйте payload та згенеруйте jwt токен
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      res.status(401).send("This user doesn't exist yet");
      return;
    }
    const isValidPassword = await user.validatePassword(password);

    if(!isValidPassword) {
      res.status(401).send('Username or password are incorrectly');
      return;
    }

    const payload = {
      _id: user._id,
    };

    const token = jwt.generate(payload);
    res.json({
      message: 'User successfully authorized',
      user,
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
};

exports.getProfile = async (req, res, next) => {
  // 1. Забороніть використання роута для неавторизованих користувачів
  // 2. У відповідь передайте дані авторизованого користувача
  res.json(req.user);
};
