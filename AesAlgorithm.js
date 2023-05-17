const aesjs = require('aes-js');
const  pbkdf2 = require('pbkdf2');
module.exports=function(req, res){
    
    if (req.body.btnID==="Encrypte"){
        if(req.body.encrypte_input==="" || req.body.encrypte_key===""){
            res.render("./AES/Aes.ejs")
        }
        else{
            
            try{
                var selectedOption = req.body.menu;
                if(selectedOption === "128"){
                    user_key=128;
                }
                else if(selectedOption==="192"){
                    user_key=192; 
                }
                else{
                    user_key=256; 
                }

                var key = pbkdf2.pbkdf2Sync(req.body.encrypte_key, 'salt', 1, user_key/ 8, 'sha512');
                var text = req.body.encrypte_input;
                var textBytes = aesjs.utils.utf8.toBytes(text);
                var aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
                var encryptedBytes = aesCtr.encrypt(textBytes);
                var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
                var encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

                res.render("./AES/Aes_encry.ejs", {
                    key:req.body.encrypte_key,
                    message:encryptedHex,
                    keybit:selectedOption
                });
            }
            catch{
                res.status(500).send('An error occurred during decryption.');
            }
            
        }
    }
    if (req.body.btnID==="Decrypte") {
        if(req.body.encrypted_message ==="" ||req.body.decryption_key===""){
            res.render("./AES/Aes.ejs")
        }
        else{
            try{
                const selectedOptions = req.body.menus;
                if(selectedOptions === "192"){
                    user_key=192;
                }
                else if(selectedOptions ==="256"){
                    user_key=256; 
                }
                else{
                    user_key=128; 
                }

                var key = pbkdf2.pbkdf2Sync(req.body.decryption_key, 'salt', 1, user_key/ 8, 'sha512');
                var aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
                encryptedBytes=aesjs.utils.hex.toBytes(req.body.encrypted_message);
                var decryptedBytes = aesCtr.decrypt(encryptedBytes);
                var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
                res.render("./AES/Aes_decry.ejs", {
                    key:req.body.decryption_key,
                    message:decryptedText,
                    keybit:user_key
                });
                }
                catch (error) {
                    res.status(500).send('An error occurred during decryption.');
                }  
        }  
    }
}