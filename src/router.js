const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const router = express.Router();

const saltRounds = 10;
const secretKey = "thisismysecretkey";

// post request for register ==========================
router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    bcrypt.hash(password, saltRounds).then( hash => {
        createUser(hash, username, res);
    })
});

// create a user ===================================
const createUser = async (hash, username, res) => {
    const user = await prisma.user.create({
        data: {
            username,
            password: hash
        }
    })
    return res.json({data: user});
} 

// post request for login===========================
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = await prisma.user.findUnique({
        where: {
            username
        }
    });

    if(!user){
        return res.status(401).send('User Not Found')
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
        const payload = { username };
        const token = jwt.sign(payload, secretKey);
        res.json({ tokenKey: token });
    }
    return res.status(401).send("password doesn't match");
});



module.exports = router;
