## Cuprins

<ul style="list-style-type:none;">
    <li><b>Variabile</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#vars1">let, mut, shadow, scope </a></li>
        <li><a href="#vars2">Practică Variabile</a></li>
    </ul>
    <li><b>Tipuri Numerice</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#num1">Tipuri Numerice </a></li>
        <li><a href="#num2">Practică Tipuri Numerice</a></li>
    </ul>
    <li><b>Char, bool, unit ()</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#cbu1">Char, bool, unit () </a></li>
        <li><a href="#cbu2">Practică Char, bool, unit ()</a></li>
    </ul>
    <li><b>Statement-uri & Expresii</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#stex1">Statement-uri si Expresii </a></li>
        <li><a href="#stex2">Practică Statement-uri si Expresii</a></li>
    </ul>
    <h2 id=""></h2>
    <li><b>Proprietății si Împrumutul</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#proprs">Proprietății RS</a></li>
        <li><a href="#imprs">Împrumutul RS</a></li>
        <li><a href="#propGemini">Proprietatea și împrumutul datelor GEMINI</a></li>
    </ul>
    <li><b>Împrumutul proprietății prin referințe</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#prop_ref1">1. & (Referință Imutabilă)</a></li>
        <li><a href="#prop_ref2">2. &mut (Referință Mutabilă)</a></li>
        <li><a href="#prop_ref3">3. *</a></li>
    </ul> 
    <li><b>Durate de viață a referintelor</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#viata1">Duratele de Viață Explicite ('a)</a></li>
        <li><a href="#viata2">Durate de viață Multiple ('a, 'b)</a></li>
        <li><a href="#viata3">Structuri cu Referințe</a></li>
    </ul>
    <li><b>Durate de viață statice</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#static1">Referințe Statice (&'static T)</a></li>
        <li><a href="#static2">'static ca o constrângere (Trait Bound T: 'static)</a></li>
    </ul>
    <li><b>Structuri de date</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#struct">Struct</a></li>
        <li><a href="#enum">Enumerari</a></li>
        <li><a href="#tuplu">Struct de tip TUPLU</a></li>
    </ul>
    <!--     
    <li><b>cap</b></li>
    <ul style="list-style-type:none;">
        <li><a href="#static1">text1</a></li>
        <li><a href="#static2">text2</a></li>
    </ul> -->
</ul>

### CONSTANTE
> **SNAKE_CASE**    
> Spre deosebire de variabile, constantelor trebuie să li se specifice explicit tipul la declarare.

```rust
const PI: f32 = 3.14159;

fn main() {
    println!(
        "Pentru a crea un măr {}, mai întâi trebuie să creezi un univers.",
        PI
    );
}

```

<h2 id="vars1">Variabile</h2>

> `let`-> Rust poate in 99% din cazuri sa auto-atribuie datatype.
> Numele variabilelor sunt `snake_case`

```rust
fn main() {

    // Rust intuiește tipul de date pentru x
    let x = 13;
    println!("x: {}", x);
    // Rust poate fi explicit in declararea tipului
    let x : f32 = 3.35;
    println!("x32: {}", x);
    // Se poate declara o variabila si se poate initializa mai tarziu
    let x;
    x = 335;
    println!("x: {}", x);
}
```

### Modificarea Variabilelor
* **mutabile** (mutable) -> Compilatorul lasa userul sa modifice valoarea var.  
* **imutabile** -> Compilatorul lasa userul doar sa citeasca valoarea.
> Valorile **mutabile** sunt declarate cu `mut` 

```rust
fn main () {
let mut var_mutabila = 5;
    println!("Variabila mutabil: {}", mutabil);
let imutabil = 33;
    println!("Var imutable: {}", imutabil);
}
```

### Ignorarea variabilelor nefolosite cu operatorul _

> Dacă cream o variabilă pe care nu o folosim,Rust ne va semnala asta. Dar uneori este util sa cream variabile pe care mai tarziu nu le folosim pentru atunci cand cream prototipuri.

```rust 
fn main(){
   let x:i32=5;
   let _y:u8=10;
}
```

### Deconstructia Variabilelor 

> `let` nu este folosit doar la legarea variabilelor, este folosit si pentru deconstruirea Variabilelor complexe.

```rust
fn main(){
   let(a, mut b):(bool,bool) =(true, false);
// a = true imutabil , b=false mutabil
   b = true;// mutabil
   assert_eq!(a, b);
}
```

### Atribuirea Deconstructivă

```rust
struct Structura{
   e: u8,
}
fn main(){
   let (a,b,c,d,e);
   (a,b) = (1,2);
// _ potrivirea unei valori , dar nu ne pasa de o valoare anume, asa ca am folosit _ in loc de un nume de variabilă 
   [c,..,d,_] = [1,2,3,4,5];
   Structura {e,..} = Structura {e:5};
   assert_eq!([1, 2, 1, 4, 5], [a, b, c, d, e]);

}
```

### Shadowing

> O a2-a variabilă declarata cu acelasi nume o va obstructiona pe cea precedentă.

```rust
fn main(){
   let x = 5; // prima
   let x = x + 1; // x : 6
   {
      let x = x * 2;
      println!("The value of x in the inner scope is: {}", x); // x : 12
   }
   println!("The value of x is: {}", x);
}
```

> Utilizarea mascării variabilelor constă în faptul că, dacă nu este nevoie să utilizați variabila anterioară într-un anumit domeniu (după ce a fost ascunsă, nu mai puteți accesa variabila anterioară cu același nume), puteți utiliza numele variabilei în mod repetat, fără a vă stoarce creierul gândindu-vă la mai multe nume.

```rust
// shadowning
let spaces = "    ";
let spaces = spaces.len();

// mut ne va da erare de tip nepotrivit 

let mut spaces = "    ";
spaces = spaces.len(); // eroare tip nepotrivit 
```

<h2 id="vars2">Practică Variabile</h2>

* **O variabilă poate fi folosita doar dacă este inițializată.**

```rust

// Fix the error below with least amount of modification to the code
fn main() {
    let x: i32 = 5; // Uninitialized but used, ERROR !
    let _y: i32; // Uninitialized but also unused, only a Warning !

    assert_eq!(x, 5);
    println!("Success!");
}
```

* **Folosește `mut` pt a marca variabila ca si mutabilă**

```rust

// Fill the blanks in the code to make it compile
fn main() {
    let mut x = 1;
    x += 2; 
    
    assert_eq!(x, 3);
    println!("Success!");
}
```

* **Domeniul de vizibilitate (Scope)**

```rust

// Fix the error below with least amount of modification
fn main() {
    let x: i32 = 10;
    {
        let y: i32 = 5;
        println!("Inner scope value of x is {} and value of y is {}", x, y);
    }
    println!("Outer scope value of x is {}", x); 
}
```

* **Scope Funcții** 

```rust

// Fix the error with the use of define_x
fn main() {
    let x = define_x();
    println!("{}, world", x); 
}

fn define_x() -> String {
    let x = "hello";
    return x.to_string();
}
```

* **Shadowing'** 

```rust

// Only modify `assert_eq!` to make the `println!` work(print `42` in terminal)
fn main() {
    let x: i32 = 5;
    {
        let x = 12;
        assert_eq!(x, 12);
    }

    assert_eq!(x, 5);

    let x = 42;
    println!("{}", x); // Prints "42".
}
```

* **Shadowing''** 

```rust

// Remove a line in the code to make it compile
fn main() {
    let mut x: i32 = 1;
    x = 7;
    // Shadowing and re-binding
    let x = x; 
    // x += 3; remove x este imubabil


    let y = 4;
    // Shadowing
    let y = "I can also be bound to text!"; 

    println!("Success!");
}
```

* **Variabile nefolosite**

```rust

fn main() {
    let _x = 1; 
}

// Warning: unused variable: `x`
```

* **1. Deconstructie tupluri cu `let`**
> Putem folosi let pentru a deconstrui un tuplu in variabile separate.

```rust

// Fix the error below with least amount of modification
// top folosește mut sau shadowing
fn main() {
    // mut
    let (mut x, y) = (1, 2);
    x += 2;
    // shadowning
    let (x,y) = (1,2);
    let x = x + 2;

    assert_eq!(x, 3);
    assert_eq!(y, 2);

    println!("Success!");
}
```

* **2. Deconstructia atributiva**

> `..` aici este folisit pentru descompunere si ignorare a unui parti din structura de date.
```rust

fn main() {
    let (x, y);
    (x,..) = (3, 4); // ignora pe 4
    [.., y] = [1, 2]; // ignora pe 1
    // Fill the blank to make the code work
    assert_eq!([x,y], [3,2]);

    println!("Success!");
} 
```

<h2 id="num1">Tipuri numerice</h2>

* **numere întregi fără semn** - 
`u8 u16 u32 u64 u128` pentru a reprezenta numere naturale -> **Unsigned**

* **numere întregi cu semn** - `i8 i16 i32 i64 i128` pentru a reprezentare numere întregi

* **numere întregi de dimensiunea unui pointer** - `usize isize` pentru a reprezenta indici și dimensiunea datelor în memorie

* **numere cu virgulă mobilă** - `f32 f64` pentru a reprezenta numere reale.

* **tuplu** - `(valoare, valoare, ...)` pentru trecerea unor secvențe fixe de valori pe **stivă**

* **tablou** - `[valoare, valoare, ...]` o colecție de elemente de **același tip**; dimensiunea colecției este fixă și devine cunoscută doar în momentul compilării

* **parte (slice)** - o parte dintr-o colecție de elemente de același tip; dimensiunea părții devine cunoscută doar în timpul rulării  
* `str` **(string slice)** - text de lungime cunoscută în timpul rulării

```rust
fn main() {
    let x = 12; // acesta este un i32 în mod implicit
    let a = 12u8;
    let b = 4.3; // acesta este un f64 în mod implicit
    let c = 4.3f32;
    let t = (13, false);
    let sentence = "hello world!";
    println!(
        "{} {} {} {} {} {} {} {} {} {}",
        x, a, b, c, d, ferris, bv, t.0, t.1, sentence
    );
}

```
### Literali numerici

|literal | exemplu |
|---|---|
| **Decimal**| 92`_`200  |   
| **Hexadecimal** | `0x`ff  |   
| **Octal** | `0o`77  |   
| **Binar**   |  `0b`1111_0000  |
| **Bit**   |   `b`'A'  |

### Conversia Numerică 

>Rust poate face **conversia de la un tip** numeric la altul, foarte ușor, folosind cuvântul cheie `as`.

```rust
fn main() {
    let a = 13u8;
    let b = 7u32;
    let c = a as u32 + b;
    println!("{}", c);

    let t = true;
    println!("{}", t as u8);
}
```
<h2 id="num2">Practică Tipuri numerice</h2>

* **1. Atribuire explicită**

```rust

// Remove something to make it work
fn main() {
    let x = 5; // am sters :i32
    let mut y: u32 = 5;

    y = x;
    
    let z = 10; // Type of z ? i32 maybe

    println!("Success!");
}
```

* **2. Conversie explicită**

```rust

// Fill the blank
fn main() {
    let v: u16 = 38_u8 as u16;

    println!("Success!");
}
```

* **3. Dacă nu atribuim specific un tip date , compilatorul va atribui una automa**t

```rust

// Modify `assert_eq!` to make it work
fn main() {
    let x = 5;
    assert_eq!("i32".to_string(), type_of(&x)); // era "u32" înainte 

    println!("Success!");
}

// Get the type of given variable, return a string representation of the type  , e.g "i8", "u8", "i32", "u32"
fn type_of<T>(_: &T) -> String {
    format!("{}", std::any::type_name::<T>())
}
```

* **4. Max**

```rust

// Fill the blanks to make it work
fn main() {
    assert_eq!(i8::MAX, 127); 
    assert_eq!(u8::MAX, 255); 

    println!("Success!");
}
```

* **5. Conversie baza**

```rust

// Modify `assert!` to make it work
fn main() {
    let v = 1_024 + 0xff + 0o77 + 0b1111_1111;
    // 1024 256 63 127
    assert!(v == 1597);

    println!("{}",v);
}
```
<h2 id="cbu1">Char, bool, unit ()</h2>

> **variabilă booleană** - `bool` pentru a reprezenta **adevărat** și **fals**. Ocupă 1 byte

```rust
fn main() {
    let x : bool = false;
    println!("X ocupă: ", size_of_val(&x));
}
```
> **caractere** - `char` pentru reprezentarea unui singur caracter **Unicode**

```rust
fn main(){
    let d = 'r'; // caracter unicode
    let ferris = '🦀'; // tot un caracter unicode
    let bv = true;
    let c = 'z';
    let z = 'ℤ';
    let g = '国';
}
```

> Pentru că Unicode are encoding de 4 byte, la fel si char ocupă 4 byte.

```rust
fn main() {
    let x = 'X';
    println!("X ocupă: ", size_of_val(&x));
}
```

* Tipul unit este (). Funcția main returnează (). Nu putem spune ca funcția main nu returnează nici o valoare, întrucât astfel de funcții snm. functii divergente( care nu pot converge). println!() returnează unit().

> Unit nu ocupă memorie.

#### Return fara valoare () unit

> Dacă pentru o funcție **NU se specifică ce tip returnează**, aceasta va **returna** un **tuplu gol**, cunoscut și sub `numele de unitate (unit)`.

> Un **tuplu gol** este reprezentat de `()`.

> Folosirea unui `()` nu este des întâlnită, dar va apărea de suficiente ori, deci este bine să știți ce se întâmplă.

```rust
fn make_nothing() -> () {
    return ();
}

// tipul pe care îl returnează este în mod implicit ()
fn make_nothing2() {
    // această funcție va returna (), dacă nu este specificat altceva pentru returnare
}

fn main() {
    let a = make_nothing();
    let b = make_nothing2();

    // Afișarea unui text de depanare pentru a și b
    // Pentru că e greu să printăm nimicul
    println!("Valoarea lui a: {:?}", a);
    println!("Valoarea lui b: {:?}", b);
}

```

---

<h2 id="cbu2">Practică Char, bool, unit ()</h2>

* **1. char**

```rust

// Make it work
use std::mem::size_of_val;
fn main() {
    let c1 = 'a';
    assert_eq!(size_of_val(&c1),4); 

    let c2 = '中';
    assert_eq!(size_of_val(&c2),4); 

    println!("Success!");
} 
```

* **2. char**

```rust

// Make it work
fn main() {
    let c1 = 'x';
    print_char(c1);
} 

fn print_char(c : char) {
    println!("{}", c);
}

```

* **3. bool**

```rust

// Make println! work
fn main() {
    let _f: bool = false;

    let t = true;
    if t {
        println!("Success!");
    }
} 
```
* **4. bool**

```rust
// Make it work
fn main() {
    let f = true;
    let t = true && true;
    assert_eq!(t, f);

    println!("Success!");
}
```

* **5. unit**

```rust

// Make it work, don't modify `implicitly_ret_unit` !
fn main() {
    let _v: () = ();

    let v = ();
    assert_eq!(v, implicitly_ret_unit());

    println!("Success!");
}

fn implicitly_ret_unit() {
    println!("I will return a ()");
}

// Don't use this one
fn explicitly_ret_unit() -> () {
    println!("I will return a ()");
}
```

* **6. unit**

```rust

// Modify `4` in assert to make it work
use std::mem::size_of_val;
fn main() {
    let unit: () = ();
    assert!(size_of_val(&unit) == 0);

    println!("Success!");
}
```

<h2 id="stex1">Statement-uri si Expresii</h2>

> Statement-urile sunt operatii care sunt executate. Obigatoriu o expresiile returneaza mereu date.

```rust
fn add_with_extra(x: i32, y:i32) -> i32 {
    let x = x + 1; // statement
    let y = y  + 5; // statement
    x + y // expresie returnata
}
```

> O expresie este evaluata si returneaza o valoare. Orice returneaza o valoare este o expresie.

```rust
fn main(){
    let y = {
        let x = 3; // scope aici
        x + 1 // valoare returnata
    }
    // y = 4 / returnat din x+1
}

```

**Exemplu**

```rust
fn main() {
    let x = 5u32;

    let y = {
        let x_squared = x * x;
        let x_cube = x_squared * x;

        // This expression will be assigned to `y`
        x_cube + x_squared + x
    };

    let z = {
        // The semicolon suppresses this expression and `()` is assigned to `z`
        2 * x;
    };

    println!("x is {:?}", x);
    println!("y is {:?}", y);
    println!("z is {:?}", z);
}
```



<h2 id="stex2">Practica ST Ex</h2>

* **1. Expresie**

```rust
// Make it work with two ways
fn main() {
   let v = {
       let mut x = 1;
       x += 2;
       x
       
   };

   assert_eq!(v, 3);

   println!("Success!");
}
```

* **2. Expresie**

```rust

fn main() {
   let v = {let x = 3; x};

   assert!(v == 3);

   println!("Success!");
}
```

* **3. Expresie**

```rust
fn main() {
    let s = sum(1 , 2);
    assert_eq!(s, 3);
}

fn sum(x: i32, y: i32) -> i32 {
    x + y
}
```

<h2 id="fct1">Funcții</h2>

> O funcție **admite** zero sau mai mulți parametri.

> În acest exemplu, funcția `add` admite doi parametri de tip `i32` (număr întreg cu semn cu dimensiune de 32 de biți).

> La **returnarea unei expresii** se poate omite cuvântul cheie return și simbolul punct-virgulă de la final, așa cum s-a procedat în funcția subtract.

> **Numele funcțiilor** sunt mereu scrise în format `snake_case`.

```rust
fn add(x: i32, y: i32) -> i32 {
    return x + y;
}

fn subtract(x: i32, y: i32) -> i32 {
    x - y
}

fn main() {
    println!("42 + 13 = {}", add(42, 13));
    println!("42 - 13 = {}", subtract(42, 13));
}

```

### Returnarea mai multor valori

> Funcțiile pot returna mai multe valori prin **returnarea unui tuplu de valori**.

> Elementele unui tuplu pot fi accesate folosind indexul acestora. `(ex: my_tuple.0)`

```rust
fn swap(x: i32, y: i32) -> (i32, i32) {
    return (y, x);
}

fn main() {
    // returnează un tuplu de valori
    let result = swap(123, 321);
    println!("{} {}", result.0, result.1);

    // destructurează tuplul în două variabile
    let (a, b) = swap(result.0, result.1);
    println!("{} {}", a, b);
}
```

---

![Functie](https://pic2.zhimg.com/80/v2-54b3a6d435d2482243edc4be9ab98153_1440w.png)

#### Puncte cheie ale functiilor  
* Functiile se pot pune oriunde, cât timp functia este definită.  
* Fiecare parametru al functiei trebuie sa aiba o eticheta cu un tip de date declarat.

#### Parametrii functiilor

> Rust este static-typed, asa ca fiecare parametru al functiei trebuie sa aiba specificat tipul sau de date.

```rust
fn main() {
    alta_functie(5, 6.1);
}

fn alta_functie(x: i32, y: f32) {
    println!("The value of x is: {}", x);
    println!("The value of y is: {}", y);
}
```

#### Valoare returnata a functiei

> Functiile sunt expresii, asa ca retuneaza valori.  
> Valoarea returnata a unei functii este ultima expresie a functiei.

```rust
fn plus_five(x:i32) -> i32 {
    x + 5
}

fn main() {
    let x = plus_five(5);

    println!("The value of x is: {}", x);
}
```

Desigur putem sa returnam o alta valoare mult mai devereme decat ultima expresie a functiei folosind `return`.

```rust
fn plus_sau_minus(x: i32) -> i32 {
    if x > 5 {
        return x
    }

    x + 5
}

fn main(){
    let x = plus_sau_minus(5);
    println!("Valoarea lui x: {}", x);
}
```

#### No return value ()

Tipul unit () este un tuplu de lungime 0, nu are nici o folosinta practica, dar poate fi folosit pentru a reprezenta ca o functie nu returneaza nimic.

* Daca o functie nu are nici un tip declarat de returnare atunci returneaza un string gol ()

```rust
use std::fmt::Debug;

fn report<T: Debug>(item: T) {
  println!("{:?}", item);

}

```
> Functia urmatoare returneaza aceasi valoare, doar ca ii spunem explicit sa returneze () prin `-> ()`

```rust
fn clear(text: &mut String) -> () {
    *text = String::from("");
}
```

#### O functie divergenta nu returneaza nimic

> Atunci cand folosim `!` ca si tip de return a functiei , indica ca functia nu  va returna nimic. In particular aceasta sintaxa este folosita pentru cazurile care programul ar da crash.

```rust
fn dead_end() -> ! {
    panic!("Mesaj de panica");
}
```

> Un alt exemplu in care cream o bucla infinita si nu va returna nimic niciodata.

```rust
fn main(){
    loop {
        // .....
    };
}
```


<h2 id="fct2">Practică Funcții</h2>

* **1. Functii**

```rust

fn main() {
    // Don't modify the following two lines!
    let (x, y) = (1, 2);
    let s = sum(x, y);

    assert_eq!(s, 3);

    println!("Success!");
}

fn sum(x: i32, y: i32) -> i32 {
    x + y
}
```

* **2. Functii**

```rust
fn main() {
   let x = print();
   println!("{}", x);
}

// Replace i32 with another type
fn print() -> &'static str {
   "Success"
}
```

* **3. Nu-l lasa sa mearga**

```rust
// Solve it in two ways
// DON'T let `println!` work
fn main() {
    never_return();
    println!("Failed!");
}
fn never_return() -> ! {
    loop {     
    };  
    panic!("Mesaj de crash");
}
```
---


<h2 id="proprs">Proprietate RS</h2>

### Stack

O stivă stochează valorile în ordine și le recuperează în ordine inversă; aceasta este cunoscută și sub numele de „Ultimul intrat, primul ieșit” (LIFO). Imaginați-vă o stivă de discuri: când adăugați mai multe discuri, le plasați deasupra stivei; când este nevoie de un disc, îl eliminați de sus. Nu puteți adăuga sau elimina discuri din mijloc sau de jos!

Adăugarea de date se numește „împingere” pe stivă, iar eliminarea datelor se numește „scoatere din stivă”.

Din cauza metodei de implementare de mai sus, toate datele din stivă trebuie să ocupe o cantitate cunoscută și fixă ​​de spațiu de memorie. Dacă dimensiunea datelor este necunoscută, nu veți putea recupera datele dorite atunci când încercați să le recuperați.

### Heap
Spre deosebire de **stive**, pentru datele a căror dimensiune este necunoscută sau se poate modifica, trebuie să le stocăm pe un heap.

Când datele sunt introduse în heap, trebuie solicitată o anumită cantitate de spațiu de memorie. Sistemul de operare găsește un spațiu gol suficient de mare undeva în heap, îl marchează ca utilizat și returnează un pointer către adresa acelei locații. Acest proces se numește alocare de memorie pe heap, uneori numit pur și simplu „alocare”.

Apoi, pointerul va fi plasat pe stivă. Deoarece dimensiunea pointerului este cunoscută și fixă, veți utiliza pointerul de pe stivă pentru a obține locația reală de memorie a datelor de pe heap și apoi veți accesa datele.

Așa cum s-a arătat mai sus, heap-ul este o structură de date căreia îi lipsește organizarea. Imaginați-vă că mergeți la un restaurant să mâncați: intrați în restaurant, îi spuneți chelnerului câte persoane sunt în grupul dvs., iar chelnerul găsește o masă goală suficient de mare (spațiu de memorie alocat pe heap) și vă conduce acolo. Dacă cineva ajunge târziu, poate găsi și locul dvs. folosind numărul mesei (un pointer pe stivă).


### Proprietatea si Stack

> Când codul apelează o funcție, argumentele transmise funcției (inclusiv pointerii către datele din heap și variabilele locale ale funcției) sunt plasate pe rând pe stivă. Când apelul funcției se termină, aceste valori sunt eliminate din stivă în ordine inversă.

> Deoarece datele din heap sunt neorganizate, este crucial să se urmărească momentul în care aceste date sunt alocate și eliberate; altfel, vor apărea scurgeri de memorie - datele nu vor fi niciodată recuperate. Aceasta este garanția puternică pe care o oferă sistemul de proprietate Rust.


### Principiile Proprietatii

* Orice valoare este detinuta de o variabila, pe care o numim proprietarul valorii.
* O valoare poate avea un singur proprietar odata.
* Cand un proprietar iese din scop, valoarea este dezalocata.

> `s` este valid din momentul declararii pana in momentul in care iese din scope.
```rust
{
    let s = "buna";
}
```

***

Pe scurt, `s` este valid din momentul în care este creat, iar validitatea sa durează până când iese din domeniul de vizibilitate (scope). După cum poți vedea, în ceea ce privește scope-ul, Rust nu este diferit de alte limbaje de programare.

### O scurtă introducere în tipul String

După cum am menționat anterior, acest capitol va folosi `String` ca exemplu, așa că vom face o scurtă introducere aici.

Am văzut deja literalii de șir `let s = "hello"`, care sunt valori de șir (de tip `&str`) hardcodate în program. Literalii de șir sunt convenabili, dar nu sunt potriviți pentru toate scenariile. Există două motive:

1.  Literalii de șir sunt imutabili (nu se pot modifica) deoarece sunt hardcodati în codul programului.
2.  Nu toate valorile șirurilor pot fi cunoscute în momentul scrierii codului.

De exemplu, dacă un șir de caractere trebuie introdus dinamic de către utilizator și stocat în memorie la runtime, atunci literalii de șir sunt complet inutili. Pentru a rezolva acest lucru, Rust oferă un tip de șir dinamic: `String`, care este alocat pe **heap** și, prin urmare, poate scala dinamic, permițând stocarea textului de dimensiuni necunoscute la compilare.

Următoarele metode pot fi utilizate pentru a crea tipuri `String` bazate pe literali:

```rust
let s = String::from("hello");
```

`::` este un operator de apelare, indicând aici invocarea unei funcții asociate `from` din tipul `String`. Deoarece tipul `String` este stocat pe heap, acesta este dinamic și îl poți modifica astfel:

```rust
let mut s = String::from("hello");

s.push_str(", world!"); // push_str() adaugă un literal la sfârșitul șirului

println!("{}", s); // Va afișa `hello, world!`
```

Acum, să revenim la subiectul principal. După ce am înțeles acest `String`, să ne uităm la interacțiunile legate de ownership (posesie).

### Interacțiunea datelor în spatele legării variabilelor (Variable Binding)

#### Transferul de Posesie (Move)

Să ne uităm mai întâi la o bucată de cod:

```rust
let x = 5;
let y = x;
```

Acest cod nu implică un transfer de posesie dintr-un motiv simplu: Codul leagă mai întâi valoarea `5` la variabila `x`, apoi copiază valoarea din `x` și o atribuie lui `y`. În cele din urmă, atât `x` cât și `y` sunt egale cu `5`. Deoarece numerele întregi sunt tipuri de date primitive în Rust și sunt valori simple de dimensiune fixă, ambele valori sunt atribuite prin copiere automată și sunt stocate pe **stivă (stack)**, nefiind necesară alocarea de memorie pe heap.

Atribuirile pe tot parcursul procesului se fac prin copierea valorilor (care se întâmplă pe stivă), deci nu este nevoie de transferul posesiei.

Unii studenți s-ar putea întreba: Această copiere nu consumă performanță? De fapt, datele de pe stivă sunt suficient de simple, iar copierea este extrem de rapidă; necesită doar copierea dimensiunii unui întreg (i32 are 4 octeți). Prin urmare, în acest caz, viteza de copiere este mult mai mare decât crearea de memorie pe heap. De fapt, tipurile primitive Rust pe care le-am discutat în capitolul anterior sunt toate atribuite prin copiere automată, la fel ca în codul de mai sus.

Să ne uităm la o altă bucată de cod:

```rust
let s1 = String::from("hello");
let s2 = s1;
```

În acest moment, cineva s-ar putea gândi: "Hmm, la fel ca mai sus, copiază conținutul lui `s1` și îl atribuie lui `s2`." De fapt, nu așa funcționează. Așa cum am menționat, Rust copiază automat tipurile primitive (stocate pe stivă), dar `String` nu este un tip primitiv și este stocat pe heap, deci nu poate fi copiat automat la fel de simplu.

De fapt, tipul `String` este un tip complex, compus din trei părți stocate pe **stivă**:
1.  Un pointer către heap.
2.  Lungimea șirului.
3.  Capacitatea șirului.

Pointerul este cel mai important, deoarece arată către memoria de pe **heap** unde este stocat conținutul real al șirului. Cât despre lungime și capacitate: capacitatea este dimensiunea memoriei alocate pe heap, iar lungimea este dimensiunea utilizată curent.

Pe scurt, tipul `String` de pe stivă indică spre un spațiu de pe heap unde sunt datele reale. Vom discuta acum două cazuri pentru codul `let s2 = s1`:

1.  **Copierea atât a datelor de pe stivă, cât și a celor de pe heap (Deep Copy):** Dacă instrucțiunea ar fi o copiere completă, atunci s-ar duplica totul, ceea ce ar avea un impact semnificativ asupra performanței. Rust nu face asta implicit.
2.  **Copierea doar a pointerului și a metadatelor (Shallow Copy):** Aceasta este foarte rapidă deoarece copiază doar pointerul (8 bytes), lungimea (8 bytes) și capacitatea (8 bytes) - total 24 bytes pe o mașină pe 64 de biți. Totuși, introduce noi probleme. Îți amintești regulile de ownership? Una dintre ele este că **o valoare poate avea un singur proprietar**.

Dacă am face o copiere simplă (shallow copy), valoarea reală de pe heap ar avea doi proprietari: `s1` și `s2`.

**Ce s-ar întâmpla dacă o valoare ar avea doi proprietari?**

Când o variabilă iese din scope, Rust apelează automat funcția `drop` pentru a curăța memoria de pe heap. Totuși, dacă două variabile `String` indică spre aceeași locație, apare o problemă: când ambele variabile ies din scope, ambele vor încerca să elibereze aceeași memorie. Acesta este un bug numit **double free** (eliberare dublă), una dintre erorile de siguranță a memoriei. Eliberarea aceleiași memorii de două ori duce la coruperea memoriei și potențiale vulnerabilități de securitate.

Prin urmare, Rust rezolvă problema în acest fel: când `s1` este atribuit lui `s2`, Rust consideră că `s1` nu mai este valid. Astfel, nu este nevoie să elibereze nimic pentru `s1` când iese din scope. Acesta este **transferul de posesie** (ownership transfer) de la `s1` la `s2`. `s1` devine invalid imediat după atribuire.

Să vedem ce se întâmplă când vechiul proprietar este utilizat după ce posesia a fost transferată:

```rust
let s1 = String::from("hello");
let s2 = s1;

println!("{}, world!", s1);
```

Deoarece Rust interzice utilizarea referințelor invalide, vei vedea următoarea eroare:

```text
error[E0382]: borrow of moved value: `s1`
 --> src/main.rs:5:28
  |
2 |     let s1 = String::from("hello");
  |         -- move occurs because `s1` has type `String`, which does not implement the `Copy` trait
3 |     let s2 = s1;
  |              -- value moved here
4 |
5 |     println!("{}, world!", s1);
  |                            ^^ value borrowed here after move
```

Acum, privind înapoi la regulile anterioare, cred că toată lumea are o înțelegere mai profundă:

1.  În Rust, fiecare valoare este deținută de o variabilă, numită proprietarul valorii.
2.  O valoare poate fi deținută doar de o singură variabilă la un moment dat.
3.  Când proprietarul (variabila) iese din scope, valoarea va fi ștearsă (dropped).

Dacă ai auzit termenii *shallow copy* și *deep copy* în alte limbaje, copierea pointerului fără date ar suna ca un shallow copy. Totuși, deoarece Rust invalidează simultan prima variabilă (`s1`), această operațiune se numește **Move** (Mutare), nu shallow copy. Exemplul de mai sus poate fi interpretat ca: `s1` a fost mutat în `s2`.

Aceasta rezolvă problema noastră anterioară; `s1` nu mai indică spre nicio dată, doar `s2` este valid. Când `s2` iese din scope, eliberează memoria. Acum ar trebui să înțelegi de ce Rust numește `let a = b` **variable binding** (legare de variabilă) și nu simplă atribuire în toate cazurile.

Să ne uităm la un alt cod:

```rust
fn main() {
    let x: &str = "hello, world";
    let y = x;
    println!("{},{}",x,y);
}
```

Crezi că acest cod va da eroare? Dacă ne referim la exemplul anterior cu `String` și mutarea, ar trebui. Dar ce se întâmplă de fapt?

Acest cod diferă fundamental de cel anterior: În exemplul anterior, `s1` deținea valoarea creată de `String::from`, în timp ce în acest exemplu, `x` doar **referențiază** șirul stocat în fișierul executabil binar ("hello, world"), fără a-l deține.

Prin urmare, în `let y = x`, se copiază doar referința; atât `x` cât și `y` se referă la același șir literal. Dacă încă nu înțelegi, nu te îngrijora; vei înțelege natural după ce vei învăța capitolul următor, "Referințe și Împrumuturi" (References and Borrowing).

### Clonarea (Deep Copy)

În primul rând, Rust nu creează niciodată automat o "copie adâncă" (deep copy) a datelor. Prin urmare, orice copiere automată poate fi considerată ieftină ca performanță.

Dacă avem într-adevăr nevoie să copiem datele `String` de pe heap, și nu doar datele de pe stivă, putem folosi o metodă numită `clone`.

```rust
let s1 = String::from("hello");
let s2 = s1.clone();

println!("s1 = {}, s2 = {}", s1, s2);
```

Faptul că acest cod rulează corect indică faptul că datele din `s1` au fost într-adevăr copiate complet în `s2`.

Dacă performanța codului este nesemnificativă (de exemplu la inițializare), poți folosi `clone` pentru a simplifica programarea. Totuși, pentru codul executat frecvent (hotspot paths), utilizarea `clone` va degrada semnificativ performanța și trebuie utilizată cu precauție!

### Copy (Shallow Copy pe stivă)

Copiile superficiale (Shallow copies) care apar doar pe stivă sunt foarte eficiente și sunt omniprezente.

Să revenim la exemplul cu numere întregi:

```rust
let x = 5;
let y = x;

println!("x = {}, y = {}", x, y);
```

Acest cod pare să contrazică ce tocmai am învățat: nu apelează `clone`, dar obține un efect similar, fără a raporta o eroare de ownership.

Motivul este că tipurile primitive, cum ar fi numerele întregi, au o dimensiune cunoscută la compilare și sunt stocate pe stivă, deci copierea valorii lor reale este rapidă. Nu există niciun motiv pentru a invalida variabila `x` după ce `y` este creat. Cu alte cuvinte, nu există diferență între shallow și deep copy aici.

Rust are o trăsătură (trait) numită `Copy`, care poate fi utilizată cu tipurile stocate pe stivă. Dacă un tip are trăsătura `Copy`, variabila veche rămâne utilizabilă după atribuire.

Ce tipuri au `Copy`? Poți verifica documentația, dar iată o regulă generală: orice grup de tipuri scalare simple are `Copy`, și nimic care necesită alocare de memorie sau resurse externe nu are `Copy`. Iată câteva tipuri `Copy`:

*   Toate tipurile de numere întregi (ex: `u32`).
*   Tipul Boolean (`bool`), valorile `true` și `false`.
*   Toate tipurile floating-point (ex: `f64`).
*   Tipul caracter (`char`).
*   Tuplurile, dacă și numai dacă toate elementele lor sunt `Copy`. De exemplu `(i32, i32)` este `Copy`, dar `(i32, String)` nu este.
*   Referințele imutabile `&T` (vezi exemplul cu string literals), dar atenție: referințele mutabile `&mut T` **NU** sunt `Copy`.

### Transmiterea valorilor și returnarea în funcții

Transmiterea unei valori către o funcție va rezulta în același eveniment: **Move** (Mutare) sau **Copy** (Copiere), la fel ca la atribuire. Codul următor demonstrează regulile de ownership și scope:

```rust
fn main() {
    let s = String::from("hello");  // s intră în scope

    takes_ownership(s);             // valoarea lui s se MUTĂ în funcție...
                                    // ... deci aici nu mai este validă

    let x = 5;                      // x intră în scope

    makes_copy(x);                  // x ar trebui mutat în funcție,
                                    // dar i32 este Copy, deci x poate fi folosit în continuare

} // Aici, x iese din scope, apoi s. Dar pentru că valoarea lui s a fost mutată,
  // nu se întâmplă nimic special.

fn takes_ownership(some_string: String) { // some_string intră în scope
    println!("{}", some_string);
} // Aici, some_string iese din scope și se apelează `drop`. Memoria este eliberată.

fn makes_copy(some_integer: i32) { // some_integer intră în scope
    println!("{}", some_integer);
} // Aici, some_integer iese din scope. Nu se întâmplă nimic special.
```

Poți încerca să folosești `s` după apelul `takes_ownership` pentru a vedea eroarea.

Similar, valorile returnate de funcții au și ele ownership:

```rust
fn main() {
    let s1 = gives_ownership();         // gives_ownership își mută valoarea returnată
                                        // în s1

    let s2 = String::from("hello");     // s2 intră în scope

    let s3 = takes_and_gives_back(s2);  // s2 este mutat în
                                        // takes_and_gives_back,
                                        // care își mută apoi valoarea returnată în s3
} // Aici, s3 iese din scope și este șters. s2 iese din scope, dar a fost mutat,
  // deci nu se întâmplă nimic. s1 iese din scope și este șters.

fn gives_ownership() -> String {             // gives_ownership va muta valoarea returnată
                                             // către funcția care o apelează

    let some_string = String::from("hello"); // some_string intră în scope.

    some_string                              // returnează some_string și o mută către apelant
}

// takes_and_gives_back ia un string și îl returnează
fn takes_and_gives_back(a_string: String) -> String { // a_string intră în scope

    a_string  // returnează a_string și o mută către apelant
}
```

<h2 id="propGemini">Proprietatea și împrumutul datelor GEMINI</h2>

### Proprietate GEMINI
> Instanțiind un tip și **legându-l** de un nume de variabilă vom crea o resursă în memorie pe care compilatorul de Rust o va valida pe tot parcursul **duratei sale de viață**.   
> Variabila de care a fost legată resursa este considerată **proprietarul** resursei.

```rust
struct Foo {
    x: i32,
}

fn main() {
    // Instanțiem structuri (Foo) și le legăm de variabile (foo)
    // pentru a crea resurse în memorie
    let foo = Foo { x: 42 };
    // foo este proprietarul
}

```

### Gestionarea resurselor bazată pe domeniul de existență

> Rust folosește finalul unui domeniu de existență ca moment pentru a destructura și a dealoca o resursă.

> Termenul pentru această acțiune se numește `drop`.

```rust
struct Foo {
    x: i32,
}

fn main() {
    let foo_a = Foo { x: 42 };
    let foo_b = Foo { x: 13 };

    println!("{}", foo_a.x);

    println!("{}", foo_b.x);
    // se renunță la foo_b aici
    // se renunță la foo_a aici
}

```

### Drop-ul este o acțiune ierarhică

> Atunci când se renunță la o structură (`drop`), mai întâi se renunță la structura efectivă, apoi la copiii acesteia individual și așa mai departe.

Detalii despre memorie:

* Prin eliberarea automată a memoriei, Rust ne asigură că vor fi mai puține pierderi de memorie.
* Se poate renunța la resurse din memorie o singură dată.

```rust
struct Bar {
    x: i32,
}

struct Foo {
    bar: Bar,
}

fn main() {
    let foo = Foo { bar: Bar { x: 42 } };
    println!("{}", foo.bar.x);
    // se renunță la foo mai întâi
    // apoi se renunță la foo.bar
}

```

### Cedarea proprietatii

> Proprietatea unei resurse din memorie (a cărei proprietar este o variabilă) poate fi cedată atunci când folosim variabila respectivă ca argument în interiorul unei funcții, noul proprietar fiind parametrul funcției.

După o **cedare a proprietății**, variabila din funcția originală nu mai poate fi folosită.

Detalii despre memorie:

* În timpul **cedării proprietății**, valoarea din memoria stivei proprietarului este copiată în memoria stivei parametrului funcției apelate.

```rust
struct Foo {
    x: i32,
}

fn do_something(f: Foo) {
    println!("{}", f.x);
    // se renunță la f aici
}

fn main() {
    let foo = Foo { x: 42 };
    // foo este cedat funcției do_something
    do_something(foo);
    // foo nu mai poate fi folosit
}

```


### Returnarea proprietății

> Proprietatea poate fi de asemenea returnată de o funcție.

```rust

struct Foo {
    x: i32,
}

fn returneaza_valoare () -> Foo {
    Foo { x : 1 }
    // proprietatea este cedata
}

fn main () {
    let foo = returneaza_valoare(); 
    // foo devine proprietar
    // drop foo

}

```

### Împrumutul proprietății prin referințe

> Referințele ne permit să împrumutăm accesul la o resursă din memorie prin operatorul `&`.

Asemănător altor resurse, se poate renunța (**drop**) și la referințe.

```rust
struct Foo {
    x: i32,
}

fn main() {
    let foo = Foo { x: 42 };
    let f = &foo;
    println!("{}", f.x);
    // se renunță la f aici
    // se renunță la foo aici
}

```

---
#### Referinte Imutabile
![Referinte Imutabile](https://pic1.zhimg.com/80/v2-fc68ea4a1fe2e3fe4c5bb523a0a8247c_1440w.jpg)

```rust
fn main() {
    let s1 = String::from("hello");

    let len = calculate_length(&s1);

    println!("The length of '{}' is {}.", s1, len);
}

fn calculate_length(s: &String) -> usize {
    s.len()
}
```


---

## & vs &mut

Acesta este unul dintre cele mai importante concepte din Rust, legat de sistemul de "Ownership" (posesie) și "Borrowing" (împrumut).

Pe scurt:
*   **`&` (Referință Imutabilă / Shared Reference):** Îți permite doar **să citești** datele. Poți avea oricâte referințe de acest tip simultan.
*   **`&mut` (Referință Mutabilă / Exclusive Reference):** Îți permite **să citești și să modifici** datele. Poți avea doar una singură activă la un moment dat.

Hai să le detaliem pe fiecare cu exemple și analogii.

---

<h3 id="prop_ref1">1. & (Referință Imutabilă)</h3>

Gândește-te la `&` ca la o **permisiune de "Read-Only"** (doar citire).
Când creezi o referință cu `&`, spui: *"Vreau să mă uit la valoarea asta, dar promit că nu o voi schimba."*

**Regula:** Poți avea oricâte referințe `&` vrei în același timp, atâta timp cât nimeni nu modifică valoarea.

**Exemplu:**
```rust
fn main() {
    let x = 10; // x este proprietarul

    let r1 = &x; // r1 împrumută x (doar citire)
    let r2 = &x; // r2 împrumută x (doar citire)

    println!("r1 este {} și r2 este {}", r1, r2);
    // Totul e OK. Ambii pot privi valoarea lui x.
}
```

<h3 id="prop_ref2">2. &mut (Referință Mutabilă)</h3>

Gândește-te la `&mut` ca la o **permisiune "Exclusivă de Scriere"**.
Când creezi o referință cu `&mut`, spui: *"Vreau să modific valoarea asta și am nevoie de acces exclusiv ca să nu apară erori."*

**Regula:** Poți avea **o singură** referință `&mut` activă la un moment dat. Dacă ai un `&mut`, nu poți avea niciun alt `&` sau `&mut` în același timp.

**Exemplu:**
```rust
fn main() {
    let mut x = 10;

    let r_mut = &mut x; // r_mut împrumută x cu drept de modificare
    *r_mut += 5;        // Modificăm valoarea la care arată r_mut

    println!("x este acum 15 (dar nu pot accesa x direct aici încă)");
    println!("Valoarea prin referință: {}", r_mut);
}
```

---

### Marea Regulă a "Borrow Checker-ului"

Rust impune aceste reguli pentru a preveni **Data Races** (conflicte de date). Gândește-te la următoarea situație: Ce s-ar întâmpla dacă `r1` citește datele exact în milisecunda în care `r2` le șterge sau le modifică? Programul ar crăpa sau ar citi gunoaie.

De aceea, Rust spune:
> Poți avea **ORI** (multe referințe imutabile `&`) **ORI** (o singură referință mutabilă `&mut`), dar **NICIODATĂ** ambele în același timp.

**Exemplul care NU merge (și de ce):**

```rust
fn main() {
    let mut x = 10;

    let r1 = &x;      // OK: Avem un cititor.
    let r2 = &mut x;  // EROARE! Nu poți cere drept de scriere cât timp r1 se uită la x.

    println!("{}", r1); // r1 se așteaptă ca x să fie 10, dar r2 l-ar putea schimba.
}
```
*Eroarea va fi: "cannot borrow `x` as mutable because it is also borrowed as immutable".*

---

### Analogie din viața reală

Imaginează-ți un document Google (Google Doc):

1.  **Scenariul `&` (Imutabil):**
    *   Trimiți linkul de "View Only" la 10 prieteni.
    *   Toți 10 pot citi documentul în același timp.
    *   Nimeni nu poate scrie. Totul este sigur și stabil.

2.  **Scenariul `&mut` (Mutabil):**
    *   Vrei să faci modificări majore. Dai afară pe toată lumea din document (revoci accesul).
    *   Rămâi singur în document (modul "Edit").
    *   Cât timp scrii tu, nimeni altcineva nu poate nici măcar să citească, pentru că ar vedea propoziții neterminate sau haos.

### Rezumat

| Caracteristica | `&` (Imutabil) | `&mut` (Mutabil) |
| :--- | :--- | :--- |
| **Drepturi** | Doar citire | Citire și Scriere |
| **Cantitate** | Nelimitate (Oricâte) | Doar una singură |
| **Coexistență** | Poate exista cu alte `&` | Nu poate exista cu nimic altceva |
| **Cuvânt cheie** | *Shared Reference* | *Exclusive Reference* |


---

<h3 id="prop_ref3">3. *</h3>

Operatorul `*` în Rust are mai multe roluri, dar cel mai important (și cel legat de întrebarea ta anterioară) este **Dereferențierea** (Dereferencing).

Dacă `&` înseamnă **"Referențiere"** (crearea unei adrese/pointer către o valoare), atunci `*` înseamnă **"Dereferențiere"** (urmărirea adresei pentru a ajunge la valoarea efectivă).

---

### Dereferențierea (Accesarea valorii)

Gândește-te la analogia anterioară:
*   `x` este **casa**.
*   `&x` este **o hârtie cu adresa casei** scrisă pe ea.
*   `*` este acțiunea de a **te urca în mașină și a merge la acea adresă** pentru a intra în casă.

În cod, `*` se folosește pentru a accesa datele din spatele unei referințe.

#### A. Citirea valorii (deși Rust o face des automat)
```rust
fn main() {
    let x = 10;
    let r = &x; // r este o referință (ține adresa lui x)

    // Aici citim valoarea.
    // *r înseamnă: "Mergi la adresa din r și dă-mi valoarea de acolo".
    println!("Valoarea este: {}", *r); 
}
```

#### B. Modificarea valorii (Foarte important!)
Aici este locul unde vei folosi `*` cel mai des manual. Când ai o referință mutabilă (`&mut`), nu poți pur și simplu să atribui o valoare referinței, trebuie să atribui valoarea **locației** spre care arată referința.

```rust
fn main() {
    let mut x = 10;
    
    // r este o referință mutabilă către x
    let r = &mut x; 

    // EROARE: r = 20; 
    // Rust ar crede că încerci să schimbi adresa de memorie (pointerul), nu valoarea.
    
    // CORECT:
    *r = 20; 
    // "Mergi la adresa stocată în r și scrie valoarea 20 acolo".
}
```

#### Un detaliu important: "Magia" operatorului `.` (Dot Operator)

Poate te întrebi: *"Dacă am o referință la un String, de ce nu scriu `(*s).len()`?"*

În C++, trebuie să faci diferența manual. În Rust, operatorul `.` (punct) face **auto-dereferencing**.
Dacă ai o referință `r` către un obiect și apelezi o metodă sau accesezi un câmp, Rust va adăuga automat `*` pentru tine.

```rust
let s = String::from("Salut");
let r = &s;

// Varianta lungă (manuală):
let len1 = (*r).len(); 

// Varianta Rust (automată):
let len2 = r.len(); // Rust știe să facă (*r).len() în spate.
```
*De aceea, în Rust vei vedea `*` mai rar decât în C/C++, de obicei doar când vrei să suprascrii valori simple (ca în exemplul cu `*r = 20`).*

---

#### Rezumat

În contextul pointerilor și al memoriei:
*   `&x` -> **Creează** o referință (Obții adresa).
*   `*r` -> **Urmărește** referința (Te duci la adresă să accesezi sau să modifici valoarea).

Dacă ai `let r = &mut x;`, atunci:
*   `r` este pointerul (adresa).
*   `*r` este valoarea (conținutul lui x).

```rust
fn main() {
    let mut foo = 42;
    let f = &mut foo;
    let bar = *f; // primim o copie a valorii proprietarului
    *f = 13;      // setăm valoarea proprietarului prin referință
    println!("{}", bar);
    println!("{}", foo);
}

```

---
## Trimiterea datelor imprumutate

Aceasta este partea practică a conceptelor `&` și `&mut`. În Rust, "trimiterea datelor împrumutate" se numește tehnic **Passing by Reference**.

Pentru a înțelege de ce facem asta, trebuie să vedem întâi ce se întâmplă dacă **NU** împrumutăm datele.

### Problema: "Mutarea" (Move)
În Rust, dacă trimiți o valoare complexă (cum ar fi un `String` sau un `Vector`) unei funcții fără să folosești `&`, acea valoare este **mutată** (moved). Asta înseamnă că proprietatea se transferă funcției, iar variabila originală devine invalidă.

**Exemplu fără împrumut (Move):**
```rust
fn main() {
    let s1 = String::from("Salut");
    
    preia_proprietatea(s1); // s1 este MUTAT în funcție

    // EROARE! Nu mai poți folosi s1 aici, pentru că funcția l-a "mâncat".
    // println!("{}", s1); 
}

fn preia_proprietatea(text: String) { // Aici text devine noul proprietar
    println!("{}", text);
} // Aici funcția se termină, iar `text` este șters din memorie (drop).
```

---

### Soluția 1: Trimiterea datelor spre Citire (`&`)

Dacă vrei ca funcția doar să citească datele, fără să le șteargă sau să le fure proprietatea, folosești `&` atât în definiția funcției, cât și la apelare.

**Cum se face:**
1.  În semnătura funcției pui `&` în fața tipului: `text: &String`.
2.  La apelarea funcției pui `&` în fața variabilei: `&s1`.

**Exemplu:**
```rust
fn main() {
    let s1 = String::from("Salut");

    calculeaza_lungimea(&s1); // Îi dăm doar o referință (o privire)

    println!("Pot folosi s1 în continuare: {}", s1); // Totul e OK!
}

// Funcția acceptă o referință la un String
fn calculeaza_lungimea(text: &String) {
    println!("Textul '{}' are lungimea {}", text, text.len());
} // Aici referința dispare, dar String-ul original rămâne neatins în main.
```
*Această funcție împrumută datele, le citește și apoi returnează controlul, fără a distruge datele originale.*

---

### Soluția 2: Trimiterea datelor spre Modificare (`&mut`)

Dacă vrei ca o funcție să modifice variabila ta, trebuie să îi trimiți o referință mutabilă.

**Cum se face:**
1.  Variabila originală trebuie să fie `mut`.
2.  În semnătura funcției pui `&mut`: `text: &mut String`.
3.  La apelare pui `&mut`: `&mut s1`.

**Exemplu:**
```rust
fn main() {
    let mut s1 = String::from("Salut"); // Trebuie să fie mutabilă

    adauga_lume(&mut s1); // O trimitem să fie modificată

    println!("Acum s1 este: {}", s1); // Va afișa "Salut Lume"
}

// Funcția acceptă o referință MUTABILĂ
fn adauga_lume(text: &mut String) {
    // Aici modificăm direct string-ul original din main
    text.push_str(" Lume"); 
}
```

---

### De ce facem asta? (Avantaje)

1.  **Performanță:**
    Dacă ai un `String` care conține tot textul din "Luceafărul", a-l trimite prin valoare (fără `&`) ar putea însemna copierea datelor în alte situații (deși Rust face Move, alte limbaje copiază). Trimiterea unei referințe `&` înseamnă că trimiți doar un pointer (o adresă de memorie), care are o dimensiune fixă și mică (64 biți pe procesoare moderne), indiferent cât de mari sunt datele.

2.  **Proprietate (Ownership):**
    Îți permite să păstrezi variabila în funcția `main` (sau funcția apelantă) pentru a o folosi și după ce ai apelat alte funcții auxiliare.


| Tip trimitere | Semnătură funcție | Apel funcție | Ce se întâmplă |
| :--- | :--- | :--- | :--- |
| **Move (Mutare)** | `fn f(x: String)` | `f(s)` | `s` dispare din `main`. Funcția devine stăpână. |
| **Borrow (Citire)** | `fn f(x: &String)` | `f(&s)` | `s` rămâne în `main`. Funcția doar "se uită". |
| **Mut Borrow (Scriere)** | `fn f(x: &mut String)`| `f(&mut s)`| `s` rămâne în `main`. Funcția o modifică. |

### Notă despre tipurile primitive
Pentru numere (`i32`, `f64`), boolean (`bool`) sau caractere (`char`), Rust face automat o **copie** când le trimiți unei funcții, pentru că sunt foarte mici și rapide.

```rust
fn main() {
    let x = 5;
    printeaza(x); // x este COPIAT, nu mutat.
    println!("{}", x); // Funcționează!
}

fn printeaza(numar: i32) {
    println!("{}", numar);
}
```
Regulile stricte de împrumut (Borrowing) sunt critice în special pentru datele alocate pe Heap (`String`, `Vec`, structuri complexe).

---
### Referințele unor referințe

Referințele pot fi folosite și pentru a referi alte referințe.

```rust
struct Foo {
    x: i32,
}

fn do_something(a: &Foo) -> &i32 {
    return &a.x; // returneaza valoarea citita din campul x dintr-o instanta Foo
}

fn main() {
    let mut foo = Foo { x: 42 };
    let x = &mut foo.x;
    println!("{}", foo); // Eroare: doar x mai poate citi sau scire acum in foo
    println!("{}", x); // x: 42
    *x = 13;
    // se renunță la x aici și putem crea o referință imutabilă
    let y = do_something(&foo); // returneaza a.x = 13
    println!("{}", y); // x: 13
    // se renunță la y aici
    // se renunță la foo aici
}

```

---

<h2 id="viata1">1. Duratele de Viață Explicite ('a)</h2>


În mod normal, Rust deduce automat cât trăiește o referință. Dar există situații în care **compilatorul este confuz** și are nevoie de ajutorul tău.

Cea mai comună situație este când o funcție:
1.  Primește **două sau mai multe** referințe.
2.  Returnează **o referință**.

Compilatorul se întreabă: *"Referința pe care o returnezi vine din primul parametru sau din al doilea? Cât timp trebuie să fie validă?"*

#### Exemplul Clasic: Funcția `longest`

Vrei o funcție care primește două string-uri și îl returnează pe cel mai lung.

```rust
// Așa NU va merge:
fn longest(x: &str, y: &str) -> &str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}
```
**Eroare:** Compilatorul spune: *"Nu știu dacă returnezi `x` sau `y`. Dacă `x` moare înainte de `y`, iar eu returnez `x`, programul va crăpa. Ajută-mă!"*

#### Soluția: Adnotarea `'a`

Trebuie să creăm o legătură între intrări și ieșire. Folosim o **etichetă generică**, de obicei notată cu `'a`.

```rust
// Citim așa: "x, y și rezultatul returnat vor trăi MĂCAR atâta timp cât trăiește 'a"
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}
```

**Ce înseamnă asta de fapt:**
Spui compilatorului: *"Nu știu exact care variabilă va fi returnată, dar îți garantez că rezultatul va fi valid atâta timp cât **AMBELE** referințe de intrare sunt valide."* (Practic, durata de viață a rezultatului va fi egală cu cea mai scurtă durată de viață dintre `x` și `y`).

---

<h2 id="viata2">2. Durate de viață Multiple ('a, 'b)</h2>

Uneori, variabilele nu au nicio legătură între ele. Dacă forțezi totul să aibă aceeași durată `'a`, s-ar putea să restricționezi codul inutil.

Să zicem că ai o funcție care primește două referințe, dar știi sigur că returnezi mereu ceva legat de prima referință, iar a doua e folosită doar pentru o comparație sau un calcul temporar.

**Exemplu:**
```rust
fn prima_parte<'a, 'b>(x: &'a str, y: &'b str) -> &'a str {
    println!("Am folosit y doar pentru afișare: {}", y);
    x // Returnăm x, deci rezultatul depinde doar de durata lui x ('a)
}
```

Aici:
*   `x` are durata de viață `'a`.
*   `y` are durata de viață `'b`.
*   Rezultatul are durata de viață `'a`.

**De ce e util?**
Îi spui compilatorului: *"Nu-mi pasă dacă `y` (durata `'b`) moare imediat după ce se termină funcția. Rezultatul meu depinde doar de `x` (durata `'a`)."* Dacă ai fi folosit `'a` pentru ambele, `y` ar fi trebuit să trăiască la fel de mult ca `x`, ceea ce uneori e imposibil.

---

<h2 id="viata3">3. Structuri cu Referințe</h2>

Acesta este un alt loc unde `'a` este OBLIGATORIU. Dacă o structură ține o referință (nu o valoare deținută), trebuie să specificăm cât trăiește acea referință.

```rust
struct Carte {
    titlu: String,      // Deține datele - OK
    continut: String,   // Deține datele - OK
}

struct Citat<'a> {
    parte: &'a str,     // Referință! Avem nevoie de lifetime.
}
// Citatul nu poate trăi mai mult decât textul din care provine.
```

---

### 4. Cât de des sunt întâlnite în realitate?

Răspuns scurt: **Depinde de ce fel de cod scrii.**

1.  **Cod de Aplicație (Web, CLI, Scripts): RAR.**
    *   În 95% din cazuri, vei folosi tipuri care dețin datele (`String`, `Vec<T>`, `Struct`-uri normale). Când deții datele, nu ai nevoie de lifetime-uri explicite.
    *   Rust are "Lifetime Elision Rules" (Reguli de omitere). Compilatorul ghicește singur în cazurile simple (ex: o funcție cu 1 intrare și 1 ieșire).

2.  **Cod de Biblioteci (Libraries) / Framework-uri: DES.**
    *   Dacă scrii cod foarte generic sau structuri de date complexe care trebuie să fie ultra-rapide (zero-copy), vei folosi referințe peste tot pentru a evita copierea memoriei. Acolo vei vedea `'a` foarte des.

3.  **Parsare de text (String Parsing): FOARTE DES.**
    *   Dacă scrii un parser (care citește un fișier uriaș și returnează bucăți din el fără să le copieze), vei folosi `&'a str` peste tot.

### Rezumat

*   **Explicit Lifetimes (`'a`)** nu schimbă durata de viață a variabilelor, ci doar **explică** compilatorului relația dintre ele (ex: "Rezultatul trăiește cât trăiește inputul").
*   **Multiple Lifetimes (`'a`, `'b`)** se folosesc când intrările sunt independente și rezultatul depinde doar de una dintre ele.
*   **Frecvență:** La început vei vedea rar. Pe măsură ce devii avansat și vrei performanță maximă (folosind referințe în structuri), le vei folosi mai des.

**Sfat:** Dacă ești începător și compilatorul îți cere lifetime-uri, întreabă-te mai întâi: *"Chiar am nevoie de o referință aici? Nu pot folosi pur și simplu un `String` (Owned type)?"*. De multe ori, clonarea datelor simplifică viața enorm până înveți bine conceptele.

---

## Durate de viață statice
`'static` este o durată de viață specială în Rust și este, probabil, cel mai ușor de înțeles concept, dar și cel mai ușor de interpretat greșit.

Pe scurt: **`'static` înseamnă că referința POATE trăi pe toată durata de execuție a programului.**

Există două situații principale în care vei întâlni `'static`:

---

<h3 id="static1">1. Referințe Statice (`&'static T`)</h3>

Aceasta este cea mai comună formă. Când vezi `&'static str`, înseamnă că datele la care se face referire nu vor dispărea niciodată cât timp rulează programul. Ele sunt "nemuritoare".

#### Exemplul: String Literals (Text hardcodat)
Orice text pe care îl scrii direct în cod între ghilimele este automat `'static`.

```rust
fn main() {
    // "Salut" este stocat direct în fișierul executabil (binar).
    // Nu este alocat pe Heap sau pe Stack. Este mereu acolo.
    let s: &'static str = "Salut, lume!";
    
    println!("{}", s);
}
```

**De ce funcționează?**
Când compilezi programul, textul "Salut, lume!" este scris într-o zonă specială de memorie (read-only data segment) a executabilului. Când rulezi programul, acel text este încărcat în memorie și stă acolo de la început până la sfârșit. Deci, o referință către el este validă oricând.

#### Exemplul: Variabile Globale (`static`)
Poți declara constante globale care au o adresă de memorie fixă.

```rust
static ANUL_CURENT: i32 = 2024;

fn main() {
    let r: &'static i32 = &ANUL_CURENT; // Putem lua o referință statică
    println!("Anul este: {}", r);
}
```

---


<h3 id="static2">2. 'static ca o constrângere (Trait Bound `T: 'static`)</h3>

Acesta este un concept mai subtil, dar foarte important când lucrezi cu **Thread-uri (concurență)**.

Când vezi o funcție care cere `T: 'static` (de exemplu `thread::spawn`), Rust nu îți cere neapărat o referință care trăiește veșnic. Îți cere un tip de date care **nu conține referințe temporare**.

Cu alte cuvinte: **"Datele astea ori trăiesc veșnic, ori sunt proprietatea ta exclusivă (Owned), deci nu depind de nimeni altcineva care ar putea muri."**

#### De ce e important?
Imaginează-ți că pornești un thread nou. Nu știi când se va termina acel thread (poate dura mai mult decât funcția `main`). Dacă thread-ul ar avea o referință către o variabilă locală din `main` care dispare, ar fi un dezastru.

De aceea, thread-urile cer `'static`:
1.  Ori le dai date care sunt `&'static` (trăiesc mereu).
2.  Ori le dai date deținute (`String`, `Vec`, `i32`) — numite **Owned Data**.

**Exemplu confuz dar corect:**
Un `String` (nu `&str`) satisface condiția `'static`!

```rust
use std::thread;

fn main() {
    let s = String::from("Date dinamice"); 
    // s NU este &'static str. Este un String alocat pe Heap care va fi șters la finalul funcției.

    // Totuși, putem să-l mutăm (move) într-un thread care cere 'static.
    thread::spawn(move || {
        // Deoarece am folosit 'move', thread-ul DEȚINE acum 's'.
        // Nimeni altcineva nu-l poate șterge.
        // Deci satisface condiția 'static bound.
        println!("{}", s);
    });
}
```

---

#### Greșeala comună

Mulți începători văd o eroare de lifetime ("reference implies a specific lifetime, but data is borrowed...") și încearcă să rezolve problema adăugând `'static` peste tot.

**NU face asta.**
Dacă încerci să faci o funcție să returneze `&'static str` dintr-un string creat dinamic, nu va merge:

```rust
// EROARE!
fn gresit() -> &'static str {
    let s = String::from("Salut");
    &s // Nu poți returna o referință la ceva ce urmează să fie șters!
       // Singurul mod în care asta ar merge e dacă 's' ar fi un string literal "Salut".
}
```

#### Rezumat

1.  **`&'static str`**: Text scris direct în cod ("hardcoded"). Trăiește cât programul. Este stocat în binar.
2.  **`static` variable**: Variabile globale declarate explicit.
3.  **`T: 'static`**: O regulă (folosită des la thread-uri) care spune: *"Datele astea nu trebuie să conțină referințe împrumutate care ar putea expira. Trebuie să fie ori deținute complet (Owned), ori referințe statice."*

În practică, vei folosi `'static` cel mai des pentru **mesaje de eroare constante** sau **configurații** care nu se schimbă niciodată.

---

<h2 id="propex">Practică Proprietate </h2>

* **1. Proprietate**

```rust

fn main() {
    // Use as many approaches as you can to make it work
    let x = String::from("Hello world");
    let y = &x;
    println!("{}, {}",x, *y);
}

fn main() {
    let x = String::from("hello, world");
    let y = x.clone();
    println!("{},{}",x,y);
}

fn main() {
    let x = &String::from("hello, world");
    let y = x;
    println!("{},{}",x,y);
}


```

* **2. Preluare Proprietate**

```rust
// Don't modify code in main!
fn main() {
    let s1 = String::from("Hello world");
    let s2 = take_ownership(s1);

    println!("{}", s2);
}

// Only modify the code below!
fn take_ownership(s: String) -> String {
    s
}
```

* **3. Cedare proprietate**

```rust

fn main() {
    let s = give_ownership();
    println!("{}", s);
}

// Only modify the code below!
fn give_ownership() -> String {
    let s = String::from("Hello world");
    s
}
```

* 4. Clona

```rust
// Fix the error without removing any code
fn main() {
    let s = String::from("Hello World");

    //print_str(s); // aici fct preia proprietatea lui s
    print_str(s.clone());
    println!("{}", s);
}

fn print_str(s: String)  {
    println!("{}",s)
}



///////////////////

// Fix the error without removing any code
fn main() {
    let s = String::from("Hello World");

    print_str(&s);

    println!("{}", s);
}

fn print_str(s: &String)  {
    println!("{}",s)
}
```

Răspunsul scurt este: **Pentru că tipul `&str` (string slice) implementează trăsătura `Copy`.**

Aici e "capcana" vizuală: `"hello"` **nu** este un `String` (heap allocated), ci este un `&str` (o referință către o zonă statică de memorie).

Hai să analizăm tuplul tău element cu element pentru a vedea de ce întregul tuplu este `Copy`.

### Regula Tuplurilor
Un tuplu `(T1, T2, T3)` este `Copy` **dacă și numai dacă** toate elementele din interiorul lui (`T1`, `T2`, `T3`) sunt la rândul lor `Copy`.

### Analiza elementelor din `x`
Tuplul tău este: `(i32, i32, (), &str)`.

1.  **`1` și `2` (`i32`)**: Sunt numere întregi. Numerele sunt stocate pe stivă. **Sunt `Copy`.**
2.  **`()` (unit type)**: Tipul gol. Are dimensiune 0. **Este `Copy`.**
3.  **`"hello"` (`&str`)**: Aici e cheia. Aceasta este o **referință imutabilă** (shared reference).
    *   În Rust, referințele imutabile (`&T`) sunt `Copy`.
    *   Când copiezi un `&str`, nu copiezi textul efectiv ("h", "e", "l"...), ci copiezi doar **pointerul** (adresa) și **lungimea**.
    *   Este foarte ieftin să copiezi o adresă de memorie.

Deoarece **toate** cele 4 elemente sunt `Copy`, Rust decide automat că întregul tuplu este `Copy`.

Astfel, `let y = x;` face o copie bit-cu-bit a tuplului pe stivă. `x` rămâne valid.

* 6. Mutabilitatea poate fi schimbata daca proritatea este transferata

```rust

// make the necessary variable mutable
fn main() {
    let mut s = String::from("Hello ");
    
    let s1 = &mut s;

    s1.push_str("World!");
    println!("{}", s);

    println!("Success!");
}

// sau 


// make the necessary variable mutable
fn main() {
    let s = String::from("Hello ");
    
    let mut s1 = s;

    s1.push_str("World!");

    println!("Success!");
}

```

* 8. Mutare Partiala

```rust

fn main() {
   let t = (String::from("hello"), String::from("world"));

   let _s = t.0.clone();

   // Modify this line only, don't use `_s`
   println!("{:?}", t);
}

// sau 


fn main() {
   let t = (String::from("hello"), String::from("world"));

   let _s = t.0;

   // Modify this line only, don't use `_s`
   println!("{:?}", t.1);
}
```

* 9. Mutare Partiala

```rust

fn main() {
   let t = (String::from("hello"), String::from("world"));

    // Fill the blanks
    let (s1, s2) = (&t.0, &t.1);

    println!("{:?}, {:?}, {:?}", s1, s2, t); // -> "hello", "world", ("hello", "world")
}
```

### Tablouri
> Un tablou este o **colecție de dimensiune fixă** de elemente care conțin **date de același tip**.

> Tipul de date pentru un tablou este scris sub forma `[T;N]`, unde `T` reprezintă **tipul** elementelor, iar `N` reprezintă **dimensiunea** **fixă** cunoscută la momentul compilării.

> Elemente **individuale pot fi accesate** cu ajutorul operatorului `[x]`, unde `x ` este un **index** `usize` (începând cu 0) al elementului pe care doriți să-l accesați.

> **Colecțiile cu dimensiune dinamică**, deseori numite **tablouri dinamice** sau variabile, vă vor fi prezentate într-un capitol viitor numit `Vectori`.

```rust
    // [TIP;NR] declarare
    let tablou: [i32;5] = [1, 2, 3, 4, 5];

    for i in 0..tablou.len() {
        print!("{:?} ", tablou[i]);
    }
    // print all
    println!("{:?}", tablou);
    println!("Element[0] = {}", tablou[0]);

```





## Capitol 2 - Control Flow
### if / else if / else 
> Condițiile nu au nevoie de paranteze! 

> Toți operatorii relaționali și logici funcționează la fel: `==`, `!=`, `<`, `>`, `<=`, `>=`, `!`, `||`, `&&`.

```rust
fn main() {
    let x = 42;
    if x < 42 {
        println!("mai puțin de 42");
    } else if x == 42 {
        println!("egal cu 42");
    } else {
        println!("mare mare de 42");
    }
}
```

### Bucle infinite
> Rust face asta într-un mod foarte simplu.

> `break` vă va arunca în afara buclei când sunteți pregătit.

```rust
fn main(){
    let mut x = 0;
    loop {
        x+=1;
        if x % 2 == 0 {
            println!("x : {} e par.",x)
        }
        if x == 42 {
            break;
        }
    }
}
```

### while loop
> `while` vă lasă să adăugați o condiție logică unei bucle.

> Dacă condiția impusă buclei devine **falsă**, bucla se va **termina**.

```rust
fn main(){
    let mut x = 0;
    while x !=42{
        x+=3;
        println!("x in while e : {}", x);
    }
}
```

### for loop

> Bucla `for` din Rust e o îmbunătățire importantă. Ea **iterează** peste valorile oricărei expresii care poate fi transformată într-un **iterator**. Vă întrebați ce este un **iterator**? Un **iterator** este un obiect pe care îl puteți întreba "Care este următorul element pe care îl ai?" până când acesta nu mai are elemente.

> **Rust** poate crea ușor `iteratori` care generează o **secvență de numere întregi**.

> Operatorul `..` creează un **iterator** care generează numere **de la un număr până la alt număr**, din unu în unu, fără să îl includă pe cel din urmă.

> Operatorul `..=` creează un **iterator** care generează numere **de la un număr până la alt număr**, din unu în unu, **inclusiv** cel din urmă.

```rust
// Bucla FOR
fn main(){
    let mut x = 0;
    // de la 0 la 4 | 0 < 5
    for x in 0..5 {
        println!("x in 0..5 : {}", x);
    }

    // de la 0 la 5 | 0 <= 5
    for x in 0..=5 {
        println!("x in 0..=5 : {}", x);
    }
}
```

### match (fostul switch)
> `match` este **exhaustiv**, deci toate cazurile trebuie să fie abordate și implementate.

> **Matching**, combinat cu destructurarea datelor, este de departe unul din cele mai întâlnite șabloane de programare pe care le veți vedea în Rust.

```rust
fn main() {
    let x = 42;

    match x {
        0 => {
            println!("am găsit zero");
        }
        // putem face un caz pentru mai multe valori
        1 | 2 => {
            println!("am găsit 1 sau 2!");
        }
        // putem face un caz pentru o mulțime
        3..=9 => {
            println!("am găsit un număr între 3 și 9 inclusiv");
        }
        // putem pune numărul care respectă cazul într-o variabilă
        matched_num @ 10..=100 => {
            println!("am găsit numărul {} între 10 și 100!", matched_num);
        }
        // acesta este cazul implicit care trebuie să existe dacă
        // nu sunt abordate toate cazurile posibile
        _ => {
            println!("am găsit alt număr!");
        }
    }

```

### Returnarea unor valori dintr-o buclă

> `loop` poate fi oprit pentru a returna o valoare.

```rust
fn main() {
    let mut x = 0;
    let v = loop {
        x += 1;
        if x == 13 {
            break "am găsit 13";
        }
    };
    println!("v={}", v);
}

```

### Returnarea unor valori din expresii block

> `if-urile`, `match-urile`, funcțiile și domeniile bloc au un mod unic de a returna valori în Rust.

> **Dacă ultima instrucțiune** din interiorul unui `if`, `match`, `funcții` sau `domeniu bloc` este o expresie fără `;`, Rust o va returna sub forma unei valori din acel bloc. 

> Acesta este un mod foarte bun de a crea o logică concisă care returnează o valoare care poate fi pusă într-o variabilă nouă.

> Observăm cum acest lucru permite unui `if` să funcționeze ca o **expresie ternară concisă**.
```rust
fn example() -> i32 {
    let x = 42;
    // expresia ternară concisă
    let v = if x < 42 { -1 } else { 1 };
    println!("din if: {}", v);

    let food = "hamburger";
    let result = match food {
        "hotdog" => "este un hotdog",
        // observați că acoladele sunt opționale când există
        // o expresie simplă de returnare
        _ => "nu este un hotdog",
    };
    println!("tipul de mâncare: {}", result);

    let v = {
        // Acest domeniu de vizibilitate ne permite să nu poluăm spațiul funcțiilor
        let a = 1;
        let b = 2;
        a + b
    };
    println!("din bloc: {}", v);

    // Modul idiomatic de a returna o valoare în Rust la sfâșitul unei funcții
    v + 4
}

fn main() {
    println!("din funcție: {}", example());
}

```

---

## Capitol 3 - Structuri de date

<h2 id="struct">Struct</h2>

> Un `struct` este o **colecție de câmpuri** (field-uri).

> **Câmpurile** sunt pe scurt date asociate unei structuri. Valorile lor pot fi de tip **primar** sau o **structură de date**.

> **NOTĂ:** Folosim `String` si nu `&str` la declarare pentru structuri pentru ca vrem ca fiecare instanță sa aibă propria sa zonă de date.

Definiția `structurii` este ca o **matriță** pentru compilator pentru a ști cum să **aranjeze câmpurile în memorie** într-un mod compact.

```rust
struct User {
    active: bool,
    username: String,
    email: String,
    sign_in_count: u64,
}
```

> Pentru a folosi un struct pe care l-am definit, trebuie sa cream o instanta.

```rust
fn main(){
    let user1 = User {
        active: true,
        username: String::from("unusername1"),
        email: String::from("unemail-ul"),
        sign_in_count: 1
    };
}
```
#### Accesarea câmpurilor unei strcturi

> Pentru a accesa valoarea unui câmp al structului folosim notatia `.`

> In cazul nostru daca vrem sa modificam un anumit camp al instantei, `daca instanta este mutabila`, schimbam prin `user1.email`

```rust
fn main(){
    let mut user1 = User{
        active: true,
        username: String::from("user1"),
        email: String::from("unemail@"),
        sign_in_count: 3
    };

    // accesare a unui camp al instantei
    user1.active = false;
}
```

#### Funcție care returnează o instanță

```rust
fn creaza_user(username: String, email: String) -> User {
    User {
        active: true,
        username: username,
        email: email,
        sign_in_count: 1
    }
}
```

> Sintaxă rapidă pentru a inițializa câmpurile atunci când au același nume

```rust
fn creaza_user(username: String, email: String) -> User {
    User{
        active: true,
        username,
        email,
        sign_in_count: 2
    }
}
```

#### Inițializare a câmpurilor unei instanțe folosind câmpurile unei alteia

```rust
fn main(){


    let mut user1 = User{
        active: true,
        username: String::from("user1"),
        email: String::from("unemail@"),
        sign_in_count: 3
    };

    // accesare a unui camp al instantei
    user1.active = false;

let mut user2 = User{
        active: true, // COPY
        email: user1.email /// !COPY->MOVE
        username: user1.username, /// !COPY->MOVE
        sign_in_count:3 // COPY
    };
}

/// .. restul câmpurilor 
let user3 = User{
    email: String::from("altexemolu@.com"),
    ..user1 ///MOVE if !COPY
};
```

#### Crearea unor tipuri diferite folosind Struct Tuplu

```rust
struct Culoare(i32,i32,i32);
struct Punct(i32,i32,i32);

fn main(){
    let black = Culoare(0,0,0);
    let origine = Punct(0,0,0);
}
```

#### Exemplu de program folosind Struct

```rust

struct Patrat {
    inaltime: i32,
    latime: i32,
}

fn main(){
    
}

fn area(patrat: &Patrat) -> u32 {
    patrat.inaltime * patrat.latime
}


```


### Apelarea metodelor

> Spre deosebire de funcții, metodele sunt funcții asociate unui tip specific de date.

> **metode statice** — metode care aparțin unui tip de date și sunt apelate folosind operatorul `::`

> **metode ale instanței** — metode care aparțin unei instanțe a unui tip de date și sunt apelate folosind operatorul `.`

```rust
fn main() {
    // Folosim o metodă statică ca să creem o instanță String
    let s = String::from("Metoda statica pentru o instanta String");
    println!("Static s = {}", s);
    println!("Static::{}, metoda.instanta={}",s,s.len());
}
```



### Memorie
Aplicațiile scrise în Rust au 3 zone de memorie unde este stocată informație:

> **memoria pentru date** - pentru date care sunt de dimensiune fixă și sunt **statice** (adică mereu disponibile pe toată durata rulării aplicației). Considerați textul din programul dumneavoastră (ex: `"Hello World!"`): memoria ocupată (bytes) de acest text este citită dintr-un singur loc în cod deci poate fi stocat în această zonă de memorie. 

>Compilatoarele fac foarte multe optimizări pentru acest tip de date și folosirea lor în general este considerată foarte rapidă, pentru că locația lor este cunoscută și fixă.

> **memoria pentru stivă (stack)** - pentru date declarate ca variabile în interiorul unei funcții (`variabile locale`). Locația în memorie a acestor date nu se schimbă pe durata apelului funcției; datorită acestui lucru compilatoarele pot optimiza codul astfel încât datele din stivă se accesează foarte rapid.

> **memoria pentru alocare dinamică (heap)** - pentru date care sunt `create în timpul rulării aplicației`. Datele în această zonă de memorie pot fi **adăugate, mutate, șterse, redimensionate, etc.** 

> Din cauza naturii sale dinamice, este în general considerată mai lentă, dar această zonă permite utilizări mult mai creative ale memoriei. Când adăugăm date în această zonă de memorie, numim această operație **alocare (de memorie)**. Când ștergem date din această zonă de memorie, numim această operație **dealocare (de memorie)**.

### Crearea datelor in memorie

> Când **instanțiem** o **structură** în codul nostru, aplicația creează câmpurile de date unul lângă altul în memorie.

> Instanțiem o structură specificând toate valorile câmpurilor în interiorul

`NumeleStructurii { ... }`

> Câmpurile unei structuri sunt accesate folosind operatorul `.`


* Textul din interiorul ghilimelelor este o dată care poate fi numai citită (ex: "Ferris"), deci acesta este pus în **zona memoriei pentru date**.

* Apelul funcției `String::from` creează o structură de tip `String` ale cărei câmpuri sunt depuse, unul lângă altul, lângă câmpurile structurii, pe stivă. Un `String` reprezintă text care poate fi modificat în următoarele moduri:

    * Se alocă memorie pe **heap** pentru text și acolo va putea fi modificat
    * Stochează o referință la acea locație de pe heap în structura `String` (Mai multe despre acest concept în următoarele lecții)
* Așadar, cei doi prieteni ai noștri, Ferris și Sarah, sunt structuri de date care vor avea mereu locații fixe în aplicația noastră, deci vor fi puși în stivă.

```rust
struct CreaturăMarină {
    tip_animal: String,
    nume: String,
    nr_mâini: i32,
    nr_picioare: i32,
    armă: String,
}

fn main() {
    // datele din CreaturăMarină sunt pe stivă
    let ferris = CreaturăMarină {
        // Struct-ul String este de asemenea pe stivă,
        // dar ține o referință a informației pe heap
        tip_animal: String::from("crab"),
        nume: String::from("Ferris"),
        nr_mâini: 2,
        nr_picioare: 4,
        armă: String::from("ghiară"),
    };

    let sarah = CreaturăMarină {
        tip_animal: String::from("caracatiță"),
        nume: String::from("Sarah"),
        nr_mâini: 8,
        nr_picioare: 0,
        armă: String::from("creier"),
    };
    
    println!(
        "{} este {}. Are {} mâini, {} picioare, și {} pe post de armă",
        ferris.nume, ferris.tip_animal, ferris.nr_mâini, ferris.nr_picioare, ferris.armă
    );
    println!(
        "{} este {}. Are {} mâini, {} picioare. Nu are nicio armă..",
        sarah.nume, sarah.tip_animal, sarah.nr_mâini, sarah.nr_picioare
    );
}

```

### Structuri de tip TUPLU

> Puteti crea structuri care sunt folosite ca un tuplu.  
> **GRUPEAZA** mai multe DT de tipuri **DIFERITE**;

```rust
struct Location(i32, i32);

fn main() {
    // Acesta este tot o structură pe stivă
    let loc = Location(42, 32);
    println!("{}, {}", loc.0, loc.1);
}
```


<h2 id="tuplu">Grupare semnatica a Struct de tip TUPLU</h2>


```rust
struct TupleStruct(i32, i32);
struct NormalStruct {
    a: i32,
    b: i32,
}

let ts = TupleStruct(1, 2);
let ns = NormalStruct { a: 1, b: 2 };

// shortcut pt a initializa campurile unui struct cu valori din alt struct
let ns2 = NormalStruct { a: 5, ..ns };
let ts2 = TupleStruct { 0: 1, ..ts }; // pt. TupleStruct are nevoie de curly brackets
                                      // si implicit numele campurilor

// Atribuire 
let TupleStruct(x, y) = ts;
println!("x: {}, y: {}", x, y);

let NormalStruct { a, b } = ns;
println!("a: {}, b: {}", a, b);

// Accesare
println!("Accessing ts by name - {}{}", ts.0, ts.1);
println!("Accessing ns by name - {}{}", ns.a, ns.b);
```

* Named structs provide clarity by explicitly naming each field, making it easier to understand the purpose of each component. Tuple structs are often shorter and more concise than named structs, making them suitable for simple wrapper types. For this purpose rust-rocket web framework package uses tuple structs


```rust
#[derive(rocket_db_pools::Database)]

#[database("postgres")]
pub struct DbConnection(rocket_db_pools::diesel::PgPool);
```

* **Grupare Semantica** atunci cand reprezentam valori RGB
```rust
struct Rgb(u8, u8, u8);
```

* Type alias for a 2D point using a tuple struct
```rust
struct Point(f64, f64);

let origin = Point(0.0, 0.0);

// Access fields of the tuple struct
println!("x: {}, y: {}", origin.0, origin.1);

```

### Creare TUPLE
```rust
let persona_cu_type : (&str,i32,f64) = ("Tony", 27, 3,5);
let persona_fara_type = ("Tony", 27, 3.5); 
```
### Decompresarea unui tuplu
```rust
let persoana_cu_type : (&str,i32,f64) = ("Tony",3,3,5);
let (nume, varsta, inaltime) = persoana_cu_type;
```

```rust
// Mutabilitate
let persoana_imutabila = ("Imutabil", 1, 1.0);
// persoana_imutabila.1 = 1;  cannot mutate
let mut persoana_mutabila = ("Mutabil", 1, 3.5);
println!("Inainte DE SCHIMBARE: {:?}", persoana_mutabila);
persoana_mutabila.0 = "Am schimbat";
println!("Dupa SCHIMBARE: {:?}", persoana_mutabila);
```


### Tuplu ca si parametrul unei functii

```rust
    /*  
        * IF ALL elementele tuplului implementeaza COPY => tuplul poate fi copiat;
        * IF ALL elementele tuplului implementeaza COPY => NU va TRASNFERA OWNERSHIP atunci este pasat unui functii FARA a folosii 1 REFERINTA;
********************************************************************************************************
        * IF pasezi o REF catre tuplu, atunci NU TRANSFERA OWNERSHIP; 
        * IF >=1 element in tuplu este NON-COPY, OWNERSHIP este transferat atunci cand este pasat unei functii FARA a folosii o REFERINTA;
    */

    /*
        IF tuplu_non-COPY-> fn x(tuplu: &(i32, String)) -> x(&tuplu_non-COPY)
        IF tuplu_COPY - > fn y(tuplu: (i32, i32)) -> y(tuplu_COPY);

     */
    // NON-COPY
    let tuplu_non_copy : (i32,String)= (10, "NOT COPY".to_string());
    afiseaza_referinte_tuplu(&tuplu_non_copy); // PRIMESTE 1 REFERINTA;

    fn afiseaza_referinte_tuplu(tuplu: &(i32,String)) { //VA primi 1 REFERINTA;
        println!("Afiseaza referinte tuplu: {}, {}", tuplu.0, tuplu.1);
    }

    // COPY
    let tuplu_copy:(i32,i32) = (10,50); 
    fn afiseaza_copy_tuplu (tuplu:(i32,i32)){
        println!("Afiseaza COPY TUPLU: {} {}", tuplu.0, tuplu.1);
    }
    afiseaza_copy_tuplu(tuplu_copy); // VA PRIMI 1 COPIE; APEL FARA REFERINTA;

    // OWNERSHIP DE LA NON-COPY cu apel FARA REFERINTA
    fn afiseaza_tuplu_ownership(tuplu_non: (i32, String)){
        println!("Afiseaza OWNERSHIP Tuplu NON-COPY cu apel fara REF: {} {}", tuplu_non.0, tuplu_non.1);
    }
    afiseaza_tuplu_ownership(tuplu_non_copy);

```


### Structuri de tip unitate

> **Structurile** nu trebuie neapărat să aibă câmpuri.
După cum am menționat în Capitolul 1, unitate este o altă denumire pentru un tuplu gol, `()`. De aceea, acest tip de structuri se numește **Unit-like**.
Acest tip de structuri este folosit rar.

```rust
struct Marcaj;
fn main(){
    let m = Marcaj;
}
```

<h2 id="enum">Enumerari</h2>

> **Enumerările** vă permit să creați un **tip nou de date** care poate avea o valoare dintr-o mulțime de elemente prestabilite folosind cuvântul cheie `enum`.

> `match` ne ajută să abordăm toate valorile posibile ale unei enumerări, făcând din acest tip un instrument puternic pentru asigurarea calității codului.

```rust
#![allow(dead_code)] // această linie oprește avertizările compilatorului

enum Specii {
    Crab,
    Caracatiță,
    Pește,
    Scoică
}

struct CreaturăMarină {
    Specii: Specii,
    nume: String,
    nr_mâini: i32,
    nr_picioare: i32,
    armă: String,
}

fn main() {
    let ferris = CreaturăMarină {
        Specii: Specii::Crab,
        nume: String::from("Ferris"),
        nr_mâini: 2,
        nr_picioare: 4,
        armă: String::from("ghiară"),
    };

    match ferris.Specii {
        Specii::Crab => println!("{} este crab",ferris.nume),
        Specii::Caracatiță => println!("{} este caracatiță",ferris.nume),
        Specii::Pește => println!("{} este pește",ferris.nume),
        Specii::Scoică => println!("{} este scoică",ferris.nume),
    }
}

```

### Enumerările care conțin tipuri de date

> Elementele unui `enum` pot avea de asemenea unul sau mai multe tipuri de date, permițându-i acestuia să se comporte ca un **union din limbajul C**.

> Atunci când un `enum` este utilizat într-un `match`, puteți atașa un nume de variabilă fiecărei valori din enum.

> Detalii despre memorie pentru un enum:

* Spațiul de memorie alocat unei variabile de tip enumerare va fi egal cu spațiul de memorie necesar pentru stocarea celui mai mare element al enumerării. Acest lucru asigură faptul că orice valoare posibilă a enumerării va încăpea în același spațiu din memorie.
* Pe lângă tipul de date al unui element (dacă acesta are un tip), fiecare element are de asemenea asociată o valoare numerică care reprezintă indexul acestuia în enumerare.

> Alte detalii:

> `enum`-ul din Rust este cunoscut și ca **uniune etichetată (tagged union)**.
> Combinarea mai multor tipuri de date pentru a crea unul nou este ceea ce îi face pe oameni să afirme faptul că Rust are tipuri algebrice.

```rust
#![allow(dead_code)] // această linie oprește avertizările compilatorului

enum Specii { Crab, Caracatiță, Pește, Scoică }
enum TipOtravă { Acid, Dureros, Letal }
enum Mărime { Mare, Mic }
enum Armă {
    Ghiară(i32, Mărime),
    Otravă(TipOtravă),
    None
}

struct CreaturăMarină {
    Specii: Specii,
    nume: String,
    nr_mâini: i32,
    nr_picioare: i32,
    Armă: Armă,
}

fn main() {
    // datele din CreaturăMarină sunt pe stivă
    let ferris = CreaturăMarină {
        // Struct-ul String este de asemenea pe stivă,
        // dar ține o referință a informației pe heap
        Specii: Specii::Crab,
        nume: String::from("Ferris"),
        nr_mâini: 2,
        nr_picioare: 4,
        Armă: Armă::Ghiară(2, Mărime::Mic),
    };

    match ferris.Specii {
        Specii::Crab => {
            match ferris.Armă {
                Armă::Ghiară(nr_ghiare, Mărime) => {
                    let mărime_descriere = match Mărime {
                        Mărime::Mare => "mari",
                        Mărime::Mic => "mici"
                    };
                    println!("ferris este un crab cu {} ghiare {}", nr_ghiare, mărime_descriere)
                },
                _ => println!("ferris este un crab cu alte arme")
            }
        },
        _ => println!("ferris este alt animal"),
    }
}
```

<h2 id="metode">Metode</h2>

> Metodele sunt funcții ale instanței. Sunt definite în contextul unui `struct`(sau `enum` sau `trait object`), iar primul lor parametru este mereu `self`, care reprezintă **instanța structurii pe care o apelează metoda**.

```rust
struct Patrat {
    latime: u32,
    inaltime: u32,
}

impl Patrat {
    fn aria(&self) -> u32 {
        self.latime * self.inaltime
    }

    fn latime(&self) -> bool {
        self.latime > 0
    }
}

fn main(){
    let patrat1 = Patrat {
        latime: 32,
        inaltime: 16,
    };

    println!("Aria patrat este: {} ", patrat1.aria());

    if patrat1.latime() {
        println!("Latimea este non-zero!");
    }
}
```

#### Metode cu mai mulți parametrii

```rust
struct Patrat {
    latime: u32,
    inaltime: u32,
}

impl Patrat {
    fn aria(&self) -> u32 {
        self.latime * self.inaltime
    }

    fn latime(&self) -> bool {
        self.latime > 0
    }

    fn can_hold(&self, alt: &Patrat) -> bool {
        self.latime > alt.latime && self.inaltime > alt.inaltime
    }
}

fn main() {
    let patrat1 = Patrat {
        inaltime: 32,
        latime: 33,
    };

    let patrat2 = Patrat{
        inaltime: 22,
        latime: 10,
    };

    let patrat3 = Patrat {
        inaltime: 100,
        latime: 50
    };

    println!("Aria patratului 1 este: {}.", patrat1.aria());

    if patrat1.latime() {
        println!("Latimea este non-zero!");
    }

    println!("Patrat 1 il poate tine pe Patrat 2?: {}", patrat1.can_hold(&patrat2));
    println!("Patrat 1 il poate tine pe Patrat 3?: {}", patrat1.can_hold(&patrat3));
}
```

#### Funcții asociative
Funcțiile asociative care nu sunt metode, sunt folosite ca și constructori `new` care v-a returna o nouă instanță a structurii.
Pentru a apela o funcție asociativă folosim operatorul `::` ex: `let sq = Patrat::sqrt(3)`

```rust
struct Patrat {
    latime: u32,
    inaltime: u32,
}

impl Patrat {

    fn new() -> Self {
        Self {
            latime: 0,
            inaltime: 0,
        }
    }
}

fn main() {
    let mut nou = Patrat::new();
    println!("Nou inaltime anterior {}", nou.inaltime);
    nou.inaltime = 55;
    println!("Nou inaltime dupa:  {}", nou.inaltime);
}
```



## Capitol 4 - Generice

### Ce sunt tipurile generice?

> Tipurile generice ne lasă să definim parțial o structură (`struct`) sau o enumerare (`enum`), permițând compilatorului să creeze o versiune definită complet în timpul compilării, bazată pe modul în care am folosit codul.

> În general, Rust poate deduce tipul final analizând instanțierea noastră, dar dacă are nevoie de ajutor, puteți oricând să instanțiați explicit folosind operatorul `::<T>`, cunoscut sub numele de `turbofish` (e un bun prieten de-ai mei!).

```rust
// Un tip de structură definit parțial
struct BagOfHolding<T> {
    item: T,
}

fn main() {
    // Observați: folosind tipuri generice, generăm tipuri create la momentul compilării
    // Turbofish ne lasă să fim expliciți
    let i32_bag = BagOfHolding::<i32> { item: 42 };
    let bool_bag = BagOfHolding::<bool> { item: true };
    
    // Rust poate deduce tipuri și pentru cele generice!
    let float_bag = BagOfHolding { item: 3.14 };
    
    // Atenție: nu puneți niciodată o geantă în altă geantă în viața reală
    let bag_in_bag = BagOfHolding {
        item: BagOfHolding { item: "boom!" },
    };

    println!(
        "{} {} {} {}",
        i32_bag.item, bool_bag.item, float_bag.item, bag_in_bag.item.item
    );
}

```

### Reprezentarea nimicului

> În alte limbaje, cuvântul cheie `null` este folosit pentru a reprezenta absența unei valori. El creează dificultăți în limbajele de programare, pentru că este posibil ca aplicația noastră să eșueze când interacționează cu o variabilă sau un câmp cu această valoare.

> Rust nu are tipul `null`, dar nu este ignorant când vine vorba de importanța reprezentării nimicului! Gândiți-vă la o reprezentare naivă folosind o unealtă pe care o cunoaștem deja.

> Alternativa `None` pentru una sau mai multe valori care pot varia este așa de des întâlnită în Rust din cauza lipsei unei valori `null`. Tipurile generice ne ajută însă să trecem de acest obstacol.

```rust
enum Item {
    Inventar(String),
    // None reprezintă absența unui element
    None,
}

struct Geantă {
    item: Item,
}

```

### Option<T>

Rust are o enumerare deja implementată numită `Option` care ne permite să reprezentăm valori care pot fi nule (`nullable`) fără să folosim `null`.

```rust
enum Option<T> {
    None,
    Some(T),
}
```
> Această enumerare este foarte comună, instanțe ale acestei enumerări pot fi create oriunde prin intermediul elementelor din enumerare `Some` și `None`.

```rust
// Un tip de structură definit parțial
struct Geantă<T> {
    // Tipul de parametru T poate fi folosit din Option
    item: Option<T>,
}

fn main() {
    // Observați: O geantă pentru i32, care nu conține nimic! Trebuie să
    // specificăm tipul, altfel Rust nu va ști ce tip poate ține geanta
    let i32_geantă = Geantă::<i32> { item: None };

    if i32_geantă.item.is_none() {
        println!("nu este nimic în geantă!")
    } else {
        println!("se află ceva în geantă!")
    }

    let i32_geantă = Geantă::<i32> { item: Some(42) };

    if i32_geantă.item.is_some() {
        println!("se află ceva în geantă!")
    } else {
        println!("nu este nimic în geantă!")
    }

    // match ne permite să destructurăm Option în mod elegant pentru
    // a gestiona toate cazurile posibile!
    match i32_geantă.item {
        Some(v) => println!("găsit {} în geantă!", v),
        None => println!("nu a fost găsit nimic"),
    }
}

```

### Result <T,E> Tratarea erorilor

> Rust are o enumerare deja implementată numită `Result` care ne permite să returnăm o valoare care poate eșua în cadrul unei instrucțiuni. Este modalitatea idiomatică în care limbajul Rust tratează posibilele erori.

```rust
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```
> Observăm ca aceste tipuri generice au multiple tipuri parametrizate **separate prin virgulă**.

> Această **enumerare este foarte comună**, instanțe ale ei pot fi create oriunde prin intermediul elementelor din enumerare `Ok` și `Err`.

```rust
fn execută_ceva_ce_poate_eșua(i:i32) -> Result<f32,String> {
    if i == 42 {
        Ok(13.0)
    } else {
        Err(String::from("acesta nu este numărul corect"))   
    }
}

fn main() {
    let result = execută_ceva_ce_poate_eșua(12);

    // match ne permite să destructurăm Result-ul într-un mod elegant
    // ca să gestionăm toate cazurile posibile
    match result {
        Ok(v) => println!("găsit {}", v),
        Err(e) => println!("Eroare: {}", e),
    }
}

```

### Main-ul care poate esua

> `main` are capacitatea de a returna un `Result`!

```rust
fn execută_ceva_ce_poate_eșua(i: i32) -> Result<f32, String> {
    if i == 42 {
        Ok(13.0)
    } else {
        Err(String::from("acesta este numărul corect"))
    }
}

// Main nu returnează nicio valoare, dar poate returna o eroare!
fn main() -> Result<(), String> {
    let result = execută_ceva_ce_poate_eșua(12);

    match result {
        Ok(v) => println!("găsit {}", v),
        Err(_e) => {
            // gestionează această eroare grațios
            
            // returneaza o nouă eroare din main care explică ce s-a întâmplat!
            return Err(String::from("ceva nu a mers bine în main!"));
        }
    }

    // Observați că folosim o unitate în interiorul unui Result Ok
    // ca să transmitem faptul că totul a mers bine
    Ok(())
}

```

### Gestionarea gratioasa a erorilor

> `Result` e atât de des întâlnit încât Rust are un operator important, `?`, pentru a le gestiona. Următoarele două afirmații sunt echivalente:

```rust
execută_ceva_ce_poate_eșua()?
```

```rust
match execută_ceva_ce_poate_eșua() {
    Ok(v) => v,
    Err(e) => return Err(e),
}
```

```rust
fn execută_ceva_ce_poate_eșua(i: i32) -> Result<f32, String> {
    if i == 42 {
        Ok(13.0)
    } else {
        Err(String::from("acesta nu este numărul corect"))
    }
}

fn main() -> Result<(), String> {
    // Uitați cât spațiu am salvat prin această metodă
    let v = execută_ceva_ce_poate_eșua(42)?;
    println!("găsit {}", v);
    Ok(())
}

```

### Gestionarea inadecvată a enumerărilor Option/Result

> Folosirea `Option`/`Result` poate fi obositoare când încercați doar să scrieți rapid niște cod. Și `Option`, și `Result` au o funcție numită `unwrap` care poate fi utilă pentru a primi o valoare rapid, dar în mod periculos. `unwrap` va fi:

* valoare din `Option`/`Result`
* `panic!`, dacă enumerarea este de tip `None`/`Err`

> Următoarele bucăți de cod sunt echivalente:

```rust
opțiunea_mea.unwrap()

match opțiunea_mea {
    Some(v) => v,
    None => panic!("un mesaj de eroare generat de Rust!"),
}
```

> În mod similar:

```rust
rezultatul_meu.unwrap()

match rezultatul_meu {
    Ok(v) => v,
    Err(e) => panic!("un mesaj de eroare generat de Rust!"),
}
```

> Fiți un bun Rustaceu și folosiți-vă de `match` când puteți face asta!

### Vectori
 Unele din cele mai utile tipuri generice sunt colecțiile. Un **vector** este o listă de dimensiune variabilă de elemente reprezentate de **structura** `Vec`.

Macro-ul `vec!` ne permite să creăm mai ușor un vector decât l-am construi manual.

`Vec` are metoda `iter()` care **creează un iterator** dintr-un vector, fiind astfel foarte ușor să punem un vector în interiorul unei bucle for.

Detalii despre memorie:


* `Vec` este o structură, dar în interior conține o referință la o listă fixă a elementelor sale din **heap**.

* Un vector începe cu o capacitate implicită; când sunt adăugate mai multe elemente decât poate conține, acesta realocă elementele sale pe heap pentru a avea o nouă listă fixă mai mare.

```rust
fn main() {
    // Putem fi expliciți cu privire la tip
    let mut i32_vec = Vec::<i32>::new(); // turbofish <3
    i32_vec.push(1);
    i32_vec.push(2);
    i32_vec.push(3);

    // Rust este foarte inteligent când vine vorba de determinarea automată a tipului
    let mut float_vec = Vec::new();
    float_vec.push(1.3);
    float_vec.push(2.3);
    float_vec.push(3.4);

    // Este un macro superb!
    let string_vec = vec![String::from("Salutare"), String::from("Lume")];

    for cuvânt in string_vec.iter() {
        println!("{}", cuvânt);
    }
}

```

---


## Capitol 6 - Siruri de caractere

### Șiruri de caractere literale

Șirurile de caractere literale (în engleză string literals) sunt întotdeauna reprezentate folosind codificarea utf-8 al setului de caractere Unicode. Șirurile de caractere literale sunt de tipul `&'static str`:

* `&` înseamnă că referențiază o locație din memorie, neavând &mut compilatorul nu va permite modificări.

* `'static` înseamnă că datele șirului de caractere vor fi disponibile până la sfârșitul programului (nu se dă drop niciodată).

* `str` înseamnă că indică o secvență de octeți ce formează întotdeauna un text valid în formatul utf-8

```rust
fn main() {
    let a: &'static str = "salut 🦀";
    println!("{} {}", a, a.len()); // salut 🦀 10
}

```

### Secvențe Escape

Este o provocare să reprezinți vizual anumite caractere, așa că secvențele escape (eng. escape codes) ne permit să le înlocuim cu un simbol.

Rust permite folosirea secvențelor escape comune ale limbajelor bazate pe C:

* `\n`- linie nouă (eng. newline)
* `\r` - carriage return
* `\t` - tab
* `\\` - bară oblică inversă (eng. backslash)
* `\0` - nul (eng. null)
* `\'` - apostrof (eng. single-quote)

```rust
fn main() {
    let a: &'static str = "Ferris spune:\t\"salut\"";
    println!("{}",a);
}
```

### Șiruri de caractere literale pe mai multe linii

Șirurile de caractere din Rust se întind, în mod implicit, pe mai multe linii.

Folosiți un `\` la sfârșitul rândului dacă nu doriți să se facă o întrerupere de rând.

```rust
fn main(){
    let haiku : &'static str = "
        Scriu si scriu
        pe mai multe randuri
        scriu
    ";

    println!("{}", haiku);
    /* 
    Scriu si scriu
    pe mai multe randuri
    scriu
    */
    println!("Saluare \
    / lume ");
    // Salutare lume
}
```

### Șiruri de caractere literale brute

Șirurile de caractere brute **(eng. raw strings**) ne permit scrierea unei secvențe de caractere, cuvânt cu cuvânt, începând cu `r#"` și terminând cu `"#`. Acest lucru ne permite să inserăm caractere care altfel ne-ar putea face să confundăm un șir de caractere normal cu unul literal (cum ar fi ghilimele duble și backslash-uri).

```rust
fn main() {
    // siruri pe mau multe linii
    let haiku : &'static str = "
        Scriu si scriu
        pe mai multe randuri
        scriu
    ";

    println!("{}", haiku);
    println!("Saluare \
    / lume ");
}
```

### Șiruri de caractere literale din fișiere

Dacă aveți un text foarte mare, luați în considerare utilizarea macroului `include_str!` pentru a include text din fișiere locale în programul dumneavoastră:

```rust
fn main(){
    // include text din alt fisier local
    let text_html = include_str!("rust.html");
    println!("{}", text_html);
}
```

### Subșiruri de caractere

Un subșir de caractere (eng. **string slice**) este o referință la o secvență de octeți din memorie ce trebuie să fie întotdeauna în format utf-8 valid. Un subșir al unui subșir (în engleză sub-slice) de str, trebuie să fie, de asemenea, în format utf-8 valid. Metode comune ale `&str`:

* `len` obține lungimea șirului literal în octeți (nu numărul de caractere).
* `starts_with` / `ends_with` pentru teste de bază.
* `is_empty` returnează true dacă lungimea este zero.
* `find` returnează un `Option<usize>` al primei poziții dintr-un text.

```rust
fn main() {
    let a = "salut 🦀";
    println!("{}", a.len());
    let primul_cuvant = &a[0..5];
    let al_doilea_cuvant = &a[6..10];
    // let jumatate_de_crab = &a[6..8]; EȘUEAZĂ
    // Rust nu accepta subsiruri formate din caractere Unicode invalide
    println!("{} {}", primul_cuvant, al_doilea_cuvant);
}

```

### Construirea șirurilor de caractere

`concat` și `join` sunt două moduri simple, dar eficiente de a construi șiruri de caractere.

```rust
    let concatenat = ["a1", "a2", "a3", "a4"].concat();
    println!("{}", concatenat);
    let joinuit = ["b1", "b2", "b3", "b4"].join(". ");
    println!("{}", joinuit);
```

### Formatarea șirurilor de caractere

Macroul `format!` ne permite să creăm un șir de caractere prin definirea unui șir parametrizat cu poziții pentru locul și modul în care trebuie plasate valorile (ex.:` {}`).

`format!` utilizează aceleași șiruri parametrizate ca și `println!`.

```rust
    let formatat = format!("aici vine concatenat {}", concatenat);
    println!("{}", formatat);
```

## OOP

Rust are o relație "complicată" cu Programarea Orientată pe Obiecte (OOP).

Dacă vii din Java, C# sau C++, vei avea un mic șoc: **Rust NU are clase (`class`) și NU are moștenire (inheritance).**

Totuși, poți scrie cod în stil OOP în Rust, doar că folosim alte "cărămizi". Hai să vedem cum se traduc conceptele clasice OOP în Rust.

---

### 1. Clase și Obiecte -> `struct` și `impl`

În limbajele clasice, o `class` conține atât datele, cât și metodele. În Rust, acestea sunt separate complet.

*   **Datele:** Sunt definite în **`struct`**.
*   **Comportamentul:** Este definit în blocul **`impl`** (implementation).

**Exemplu:** Să creăm o clasă "ContBancar".

```rust
// 1. Definim structura (DATELE)
pub struct ContBancar {
    titular: String,
    sold: f64,
}

// 2. Definim metodele (COMPORTAMENTUL)
impl ContBancar {
    // "Constructorul" (prin convenție se numește new, dar e o funcție statică)
    pub fn new(nume: String, suma_initiala: f64) -> ContBancar {
        ContBancar {
            titular: nume,
            sold: suma_initiala,
        }
    }

    // Metodă care citește (folosește &self - referință imutabilă)
    pub fn arata_sold(&self) {
        println!("Soldul lui {} este {}", self.titular, self.sold);
    }

    // Metodă care modifică (folosește &mut self - referință mutabilă)
    pub fn depune(&mut self, suma: f64) {
        self.sold += suma;
    }
}

fn main() {
    let mut cont = ContBancar::new(String::from("Ion"), 100.0);
    cont.depune(50.0);
    cont.arata_sold();
}
```

**Observații:**
*   **Encapsulare:** Folosim cuvântul cheie `pub` pentru a face datele sau metodele publice. Dacă nu pui `pub`, ele sunt private (vizibile doar în modulul curent).
*   **`self`:** Este echivalentul lui `this` din alte limbaje. Vezi cum se leagă de lecția trecută?
    *   `&self` -> Metoda doar citește datele obiectului.
    *   `&mut self` -> Metoda modifică datele obiectului.

---

### 2. Moștenire (Inheritance) -> `trait`

Aici e diferența majoră. **Rust nu te lasă să faci `class Caine extends Animal`.**
Rust folosește principiul **"Composition over Inheritance"** (Compoziție în loc de Moștenire) și **Traits** (Trăsături).

Gândește-te la un **Trait** ca la o **Interfață** din Java/C#. Un Trait definește un set de comportamente pe care un tip de date *le poate avea*.

În loc să spui "Câinele **ESTE** un Animal", spui "Câinele **IMPLEMENTEAZĂ** comportamentul de Animal".

**Exemplu:**

```rust
// Definim un Trait (Interfață)
trait Animal {
    fn scoate_sunet(&self); // Doar semnătura
}

struct Caine {
    nume: String,
}

struct Pisica {
    nume: String,
}

// Implementăm trait-ul pentru Caine
impl Animal for Caine {
    fn scoate_sunet(&self) {
        println!("{} zice: Ham!", self.nume);
    }
}

// Implementăm trait-ul pentru Pisica
impl Animal for Pisica {
    fn scoate_sunet(&self) {
        println!("{} zice: Miau!", self.nume);
    }
}
```

---

### 3. Polimorfism

Polimorfismul înseamnă abilitatea de a trata tipuri diferite (Câine, Pisică) în același mod, atâta timp cât respectă regulile (Trait-ul `Animal`).

În Rust, avem două tipuri de polimorfism:

#### A. Polimorfism Static (Generics) - Foarte rapid
Compilatorul generează câte o versiune a funcției pentru fiecare tip concret.

```rust
// Acceptă ORICE tip T care implementează Animal
fn fa_galagie<T: Animal>(animal: T) {
    animal.scoate_sunet();
}

fn main() {
    let c = Caine { nume: String::from("Azorel") };
    fa_galagie(c); // Se rezolvă la compilare
}
```

#### B. Polimorfism Dinamic (Trait Objects) - Flexibil
Asta seamănă cel mai mult cu OOP-ul clasic (Java/Python). Folosim pointeri (`Box` sau `&`) și cuvântul cheie `dyn` (dynamic). Este util când vrei o listă mixtă de animale.

```rust
fn main() {
    // Un vector care ține pointeri către orice implementează Animal
    let animale: Vec<Box<dyn Animal>> = vec![
        Box::new(Caine { nume: String::from("Azorel") }),
        Box::new(Pisica { nume: String::from("Tom") }),
    ];

    for a in animale {
        // Rust se uită la runtime ce tip este de fapt și apelează metoda corectă
        a.scoate_sunet(); 
    }
}
```
*Notă: Folosim `Box` pentru că animalele au dimensiuni diferite în memorie, dar pointerul `Box` are dimensiune fixă, deci le putem pune în același vector.*

---

### Rezumat: Traducător OOP -> Rust

| Concept OOP Clasic | Echivalent în Rust | Notă |
| :--- | :--- | :--- |
| **Class** (Clasă) | **Struct** (Date) + **Impl** (Metode) | Separare clară între date și cod. |
| **Object** (Instanță) | O valoare a structurii | Ex: `let x = Caine { ... }` |
| **Constructor** | Funcție statică (ex: `new`) | Nu există constructori speciali, e doar o convenție. |
| **Interface** | **Trait** | Foarte similar. |
| **Inheritance** (Moștenire) | **NU EXISTĂ** | Se folosesc **Traits** pentru comportament comun și **Compoziție** (struct în struct) pentru date comune. |
| **Polymorphism** | **Generics** sau **Trait Objects** (`dyn`) | Static (performanță) sau Dinamic (flexibilitate). |
| **Destructor** | Trait-ul **`Drop`** | Rulează automat când variabila iese din scope. |

### Concluzie
În Rust nu construiești ierarhii complexe de clase (Părinte -> Copil -> Nepot). În schimb, creezi structuri mici și simple, apoi le "lipești" capabilități (Traits) ca niște insigne.

*   Are nevoie să fie afișat? Îi pui Trait-ul `Display`.
*   Are nevoie să fie copiat? Îi pui Trait-ul `Clone`.
*   Are nevoie să latre? Îi pui Trait-ul `Animal`.

Este o abordare mai modulară și mai puțin predispusă la erori decât moștenirea adâncă.





