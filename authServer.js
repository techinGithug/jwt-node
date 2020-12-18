require('dotenv').config()

const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")

app.use(express.json())

let refreshTokens = []

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.statusCode(204)
});

app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    if(refreshToken == null) return res.statusCode(401)
    if(!refreshTokens.includes(refreshToken)) return res.statusCode(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return  res.statusCode(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken})
    })
});

app.post("/login", (req, res) => {
    // Authenticate User
    const username = req.body.username
    const user = { name: username }

    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.json({accessToken: accessToken, refreshToken: refreshToken})
});

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
}

app.listen(4000, (err) => {
    if(err) {
        console.log(err)
    } else {
        console.log("authServer listening on port 4000")
    }
});