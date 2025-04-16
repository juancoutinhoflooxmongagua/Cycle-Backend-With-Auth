const jwt = require('jsonwebtoken')
const env = require('../../.env')

module.exports = {
    if (req, res, next) {
        const token = req.body.token || req.query.token || req.headers['authorization']
        if (!token) {
            return res.status(403).send({ errors: ['Nenhum token fornecido.'] })
        }
        jwt.verify(token, env.authSecret, function(err, decoded) {
            if (err) {
                return res.status(401).send({ errors: ['Falha ao autenticar o token.'] })
            } else {
                req.decoded = decoded
                next()
            }
        })
    }
}