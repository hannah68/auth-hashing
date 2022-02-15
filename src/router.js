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
    const hash = await bcrypt.hash(password, saltRounds);
    
    const user = await prisma.user.create({
        data: {
            username,
            password: hash
        }
    })
    return res.json(user);
});


// post request for login===========================
router.post('/login', async (req, res) => {
    const { loginUsername, loginPassword } = req.body;
  
    const user = await prisma.user.findUnique({
        where: {
            username: loginUsername
        }
    });
   
    if(!user){
        return res.status(401).send('User Not Found')
    }

    const match = await bcrypt.compare(loginPassword, user.password);
    if (match) {
        const payload = { loginUsername };
        const token = jwt.sign(payload, secretKey);
        return res.json(token);
    }
    return res.status(401).send("password doesn't match");
});



module.exports = router;
