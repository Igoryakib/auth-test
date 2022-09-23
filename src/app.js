const express = require('express');
const volleyball = require('volleyball');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

require('./config/db');
require('./config/passport');

const apiRouter = require('./routes/api');

const app = express();

app.use(express.json());
app.use(volleyball);
app.use(helmet());
app.use(cors({ origin: '*' }));

app.use('/api/v1', apiRouter);

module.exports = app;
