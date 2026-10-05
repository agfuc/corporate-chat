const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const {
    findUserForAuthentication,
} = require(
    "../queries/postgresQueryService"
);


/*
 * Erro especÃ­fico da camada
 * de autenticaÃ§Ã£o.
 */
class AuthenticationError
    extends Error {

    constructor(
        code,
        message,
        details = {}
    ) {

        super(message);

        this.name =
            "AuthenticationError";

        this.code =
            code;

        this.details =
            details;
    }
}


/*
 * Realiza autenticaÃ§Ã£o do usuÃ¡rio.
 */
async function authenticateUser(
    email,
    password
) {

    if (
        !email ||
        typeof email !== "string" ||
        !password ||
        typeof password !== "string"
    ) {

        throw new AuthenticationError(

            "INVALID_CREDENTIALS",

            "E-mail ou senha invÃ¡lidos."
        );
    }


    const user =
        await findUserForAuthentication(
            email
        );


    if (!user) {

        throw new AuthenticationError(

            "INVALID_CREDENTIALS",

            "E-mail ou senha invÃ¡lidos."
        );
    }


    const passwordMatches =
        await bcrypt.compare(
            password,
            user.password_hash
        );


    if (!passwordMatches) {

        throw new AuthenticationError(

            "INVALID_CREDENTIALS",

            "E-mail ou senha invÃ¡lidos."
        );
    }


    if (
        user.status !==
        "ACTIVE"
    ) {

        throw new AuthenticationError(

            "USER_INACTIVE",

            "UsuÃ¡rio inativo.",

            {
                user_id:
                    user.user_id,
            }
        );
    }


    const jwtSecret =
        process.env.JWT_SECRET;


    if (!jwtSecret) {

        throw new AuthenticationError(

            "JWT_SECRET_NOT_CONFIGURED",

            "JWT_SECRET nÃ£o configurado."
        );
    }


    const token =
        jwt.sign(

            {
                user_id:
                    user.user_id,

                email:
                    user.email,

                is_admin:
                    user.is_admin,
            },

            jwtSecret,

            {
                expiresIn:
                    "8h",
            }
        );


    return {

        token,

        user: {

            user_id:
                user.user_id,

            name:
                user.name,

            email:
                user.email,

            is_admin:
                user.is_admin,
        },
    };
}


module.exports = {

    AuthenticationError,

    authenticateUser,
};
