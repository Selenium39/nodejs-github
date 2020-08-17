const controller = require('../controller')

const router = require('koa-router')()

router.post('/user/login', controller.auth.login);

router.get('/github',controller.auth.githubLogin)

module.exports = router
