import { v4 as uuid } from 'uuid';
import joi from 'joi';
import bcrypt from 'bcrypt';


export async function signIn(request, response) {

    const { email, password } = request.body;

    const loginSchema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().required()
    });

    const { error } = loginSchema.validate( request.body );
    if (error) return response.status(400).send(error.details[0].message);

    try {
        
        await startConectionToDB();
        
        const user = await db.collection('users').findOne({ email });
        if (!user) return response.status(401).send('Usuário não cadastrado!');
        
        const isValidPw = bcrypt.compareSync(password, user.encryptedPw);
        if (!isValidPw) return response.status(401).send('Email ou senha inválidos!');
        
        const token = uuid();
        
        const session = {
            _id: user._id,
            userName: user.name,
            token
        };
        
        await db.collection('sessions').insertOne(session);
        
        response.status(202).send(session);
        client.close();

    } catch (error) {
        response.status(500).send('Erro do servidor!');
        client.close();
    };
};