const { username, password } = require('./mongoauth');
var express = require('express')
const app = express()
require(`dotenv`).config({ path: '../.env' });
const cors = require('cors')
// const port = 8000
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 8000;
const cookie_parser = require("cookie-parser")
const mongoose = require('mongoose')
const routes = require('./routes/auth')
const category = require('./routes/category')
const passport = require('passport');
var path = require('path');

app.enable("trust proxy")

app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
}));
app.use(express.static(path.join(__dirname, 'uploads')));
app.use(cookie_parser())
app.use(express.json())
app.use(passport.initialize())
app.use(passport.session())

// mongoose.connect(`mongodb+srv://${username}:${password}@cluster0.48bosfo.mongodb.net/`,{
mongoose.connect(`mongodb://localhost:27017/`, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true
})

mongoose.connection.on('connected', () => {
    console.log('Database connected !')
})

app.use('/', routes)
app.use('/', category)


app.listen(PORT, () => console.log(`Listening to port ${PORT} !!`))
