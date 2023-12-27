//Imports
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//Models
const User = require("./models/User");

const app = express();
app.use(express.json());

//Open route
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Bem vindo a API" });
});

//Private route
app.get('/users/:id', async (req, res) => {
    
    const id = req.params.id
    const user = await User.findById(id, "-password")

    if(user){
        console.log("Usuario localizado")
        res.status(200).json(user)
    }else{
        console.log('Usuario nao localizado')
        res.status(404).json({ msg: 'Usuario nao localizado' });
    }
});


//User register
app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name) {
        return res.status(422).json({ msg: "Nome obrigatório" });
    }
    if (!email) {
        return res.status(422).json({ msg: "Email obrigatório" });
    }
    if (!password) {
        return res.status(422).json({ msg: "Senha obrigatória" });
    }
    if (password !== confirmPassword) {
        return res.status(422).json({ msg: "Senha não confere" });
    }
    const userExist = await User.findOne({ email: email });

    //Check if user already exists in database
    if (userExist) {
        return res.status(422).json({ msg: "Email já cadastrado, ultilize outro" });
    }

    //Create user password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //Create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();
        res.status(201).json({ msg: "usuario criado com sucesso" });
    } catch (err) {
        return res.status(500).json({ msg: "Ocorreu um erro ao criar o usuario" });

    }
});

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    //Validations
    if (!email) {
        return res.status(422).json({ msg: "Email obrigatório" });
    }
    if (!password) {
        return res.status(422).json({ msg: "Senha obrigatória" });
    }

    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(422).json({ msg: "Usuario não localizado" });
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(404).json({ msg: "Senha invalida" });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign({ id: user._id }, secret);
        res.status(200).json({ msg: "usuario autenticado", token });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            msg: "Erro no servidor, tente novamente",
        });
    }
});

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;
mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster.rybkc7w.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        //Server listening
        app.listen(3001);
        console.log("Server listening port: 3001");
    })
    .catch((err) => {
        console.log(err);
    });
