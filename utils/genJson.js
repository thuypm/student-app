const fs = require("fs");
let array = [];

for (let i = 22; i <= 59; i++) {
  for (let j = 1; j <= 43; j++) {
    array.push({
      studentId: j,
      week: i,
      point: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    });
  }
}
fs.writeFile("file.json", JSON.stringify(array), "utf8", function (err) {
  if (err) {
    console.log("An error occured while writing JSON Object to File.");
    return console.log(err);
  }

  console.log("JSON file has been saved.");
});
