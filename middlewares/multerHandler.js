const fs = require('fs');
const path = require('path');
const multer = require('multer');

const fileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dest = 'uploads/';
        let stat;
        try {
            stat = fs.statSync(dest);
        } catch (err) {
            fs.mkdirSync(dest);
        }
        if (stat && !stat.isDirectory()) {
            cb('Directory cannot be created because an inode of a different type exists at "' + dest + '"');
        }else{
            cb(null, dest)
        }
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname+ '-' + Date.now() + '-' + file.originalname);
    }
});
  
const fileFilter = (req, file, cb) => {
    if (
      file.mimetype === 'image/png' ||
      file.mimetype === 'image/jpg' ||
      file.mimetype === 'image/jpeg' 
    ) {
      cb(null, true);
    } else {
      cb(null, false);
    }
};

module.exports = multer({ storage: fileStorage, fileFilter: fileFilter });