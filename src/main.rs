use std::io;
use rand::Rng;

fn main() {
    println!("Guess the number!");
    let secret_number = rand::thread_rng().gen_range(1, 101);
    println!("The secret number is: {}", secret_number);

    println!("Please input your guess.");
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();

    let number = line.trim().parse().unwrap();
    if secret_number < number {
        println!("<");
    } else if secret_number > number {
        println!(">");
    } else {
        println!("==");
    }
}
