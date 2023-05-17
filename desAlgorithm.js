const Encryption = require('node_triple_des');
module.exports=function(req, res){
    if(req.body.btnID==="Encrypte"){

        if(req.body.encrypte_input==="" || req.body.encrypte_key===""){
            res.render("./triple_des/des.ejs")
            return;
        }
        else{
  
            try{
                const encrypt =  Encryption.encrypt(req.body.encrypte_key, req.body.encrypte_input);
                res.render("./triple_des/des_encry.ejs", {
                    key:req.body.encrypte_key,
                    message:encrypt
                })
                }
                catch (error) {
                    res.status(500).send('An error occurred during encryption.');
                } 
        }

    }
    if(req.body.btnID==="Decrypte") {
        if(req.body.encrypted_message==="" || req.body.decryption_key===""){
            res.render("./triple_des/des.ejs")
            return;
        }

      try{
          const decrypt =  Encryption.decrypt(req.body.decryption_key, req.body.encrypted_message);
          res.render("./triple_des/des_decry.ejs", {
              key:req.body.decryption_key,
              message:decrypt
          })
          }
          catch (error) {
            res.render("./triple_des/error.ejs");
          }
    }
}