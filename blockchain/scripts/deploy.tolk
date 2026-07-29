import "@acton/io"
import "@acton/emulation/scripts"

import "@wrappers/Counter.gen"

fun main() {
    val deployer = scripts.wallet(
        promptWallet("Select wallet")
    );

    val counter = Counter.fromStorage({
        owner: deployer.address,
        id: 1,
        counter: 0,
    });

    println("Deploying {}", counter.address);

    counter.deploy(
        deployer.address,
        { value: ton("0.05") }
    ).waitForTrace();
}
