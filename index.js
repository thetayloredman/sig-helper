// Signature Helper

const inquirer = require('inquirer');
const chalk = require('chalk');
const rsa = require('node-rsa');
const fs = require('fs').promises;
const crypto = require('crypto');

(async () => {
    let i = (
        await inquirer.prompt({
            type: 'list',
            name: 'mode',
            message: 'What do you want to do?',
            choices: [
                'Generate keypair',
                'Validate signature',
                'Sign document',
            ],
        })
    ).mode;
    i = i === 'Generate keypair'
            ? 'gen'
            : i === 'Validate signature'
            ? 'val'
            : i === 'Sign document'
            ? 'sgn'
            : '';

    if (i === 'gen') {
        let bits = (await inquirer.prompt({ type: 'input', name: 'bits', message: 'How many bits?', default: '2048' })).bits;
        if (isNaN(bits)) {
            throw new Error('Invalid bits passed.');
        }
        bits = Number(bits);

        let key = new rsa({ b: bits });
        let keys = {
            public: key.exportKey('public'),
            private: key.exportKey('private')
        }

        console.log(chalk.green('OK: Key generation complete.'));
        console.log('');
        console.log(chalk.green.bold('Wrote your keys to ./public-key and ./private-key.'))
        await fs.writeFile('./private-key', keys.private);
        await fs.writeFile('./public-key', keys.public);
    } else if (i === 'val') {
        let pubKey = new rsa(await fs.readFile((await inquirer.prompt({ type: 'input', name: 'path', message: 'Enter the path to the public key of the signature' })).path, 'utf8'));
        let document = await fs.readFile((await inquirer.prompt({ type: 'input', name: 'path', message: 'Enter the raw document path' })).path, 'utf8');
        let sig = (await inquirer.prompt({ type: 'input', name: 'sig', message: 'Enter the provided document signature' })).sig;

        let madeSig = crypto.createHash('sha256').update(document).digest('hex');
        let decSig = pubKey.decryptPublic(sig, 'utf8');
        
        if (madeSig !== decSig) {
            console.log(chalk.red.bold('THE SIGNATURE IS INVALID. THIS DOCUMENT MAY HAVE BEEN MODIFIED.'));
            console.log('');
            console.log(chalk.red('Given signature hash: ') + decSig);
            console.log(chalk.green('Actual hash: ') + madeSig)
        } else {
            console.log(chalk.green.bold('This document is signed and verified.'))
        }
    } else if (i === 'sgn') {
        let privKey = new rsa(await fs.readFile((await inquirer.prompt({ type: 'input', name: 'path', message: 'Enter the path to the private key of the signature' })).path, 'utf8'));
        let dPath = (await inquirer.prompt({ type: 'input', name: 'path', message: 'Enter the raw document path' })).path
        let document = await fs.readFile(dPath, 'utf8');

        let madeSig = privKey.encryptPrivate(crypto.createHash('sha256').update(document).digest('hex'), 'base64');
        
        console.log(chalk.green.bold('Document signed. Signature: ') + madeSig);
        console.log(chalk.green.bold('Wrote signed-' + dPath + ' with the signed document.'));
        await fs.writeFile('signed-' + dPath, `========== BEGIN SIGNED DOCUMENT ==========
${document}
========== END SIGNED DOCUMENT ==========
Signature: ${madeSig}`);
    }
})();
