const axios = require('axios')
const querystring = require('querystring')

const config = {
    client_id: "040f3ffa62dc8853846d",
    client_secret: "b241b70993ab18260cc16261d841186e07821a37"
}
class AuthController {
    async login(ctx) {
        let res;
        let conn;
        try {
            conn = await ctx.db.getConnection();
            const { username, password } = ctx.request.body;
            const users = await ctx.db.query(conn, 'SELECT * FROM user WHERE username = ?', [username])
            if (users.length === 0) {
                res = { ...ctx.errCode.LOGIN_ERROR }
            } else {
                const verify = await ctx.crypto.verifyPassword(password, users[0].salt, users[0].password);
                if (verify) {
                    const token = await ctx.jwt.createToken({ id: users[0].id, username: users[0].username });
                    res = { ...ctx.errCode.SUCCESS, data: { token } };
                    ctx.cookies.set('token', token, {
                        maxAge: ctx.config.jwt.expire * 1000,
                    });
                } else {
                    res = { ...ctx.errCode.LOGIN_ERROR };
                }
            }
        } catch (error) {
            ctx.logger.error(error);
            res = { ...ctx.errCode.INTERNAL_SERVER_ERROR };
            if (ctx.app.env === 'dev') {
                res.data = error.toString();
            }
        } finally {
            ctx.db.releaseConnection(conn);
            ctx.body = res;
        }
    }

    async githubLogin(ctx) {
        const code = ctx.request.query.code
        const params = {
            client_id: config.client_id,
            client_secret: config.client_secret,
            code: code
        }
        let res = await axios.post('https://github.com/login/oauth/access_token', params)
        console.log(res)
        const token = querystring.parse(res.data).access_token
        ctx.cookies.set('token', token, {
            maxAge: ctx.config.jwt.expire * 1000,
        });
        res = { ...ctx.errCode.SUCCESS, data: { token } };
        ctx.redirect('http://172.25.78.33:8081/login/success?token='+token)
    }
}
module.exports = exports = new AuthController();