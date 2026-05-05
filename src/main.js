function calculateTotal(items) {
    let total = 0;  // SonarQube 会建议用 const
    for (var i = 0; i < items.length; i++) {  // var 会被标记为代码坏味道
        total = total + items[i].price;
    }
    return total;
}

function unusedFunction() {  // 这个函数没被使用，会被检测到
    console.log("这段代码永远不会执行");
}

module.exports = { calculateTotal };