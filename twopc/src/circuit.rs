
// Input for each party in the circuit.
pub enum PartyInput {
    A(u32),
    B(u32),
}

// Represents the information of the binary gate. We only needs 4 bits to represent the gate.
// For example, the gate information for an AND gate would be 1000, for an OR gate would be 1110, etc.
pub struct GateInfo(pub u8);

// Represents the circuit. It can be an input, a gate or a combination of gates.
pub enum Circuit {
    Input(PartyInput),
    Gate(GateInfo, Box<Circuit>, Box<Circuit>),
}


// Returns the number of inputs for each party in the circuit.
// This code is adapted from: https://github.com/cronokirby/yao-gc/blob/813443e9334f01ae29fe5919a530d6a270a7e9dd/src/circuit/mod.rs#L41
pub fn get_number_of_inputs(circuit: &Circuit) -> (u32, u32) {
    let mut num_a = 0;
    let mut num_b = 0;

    match circuit {
        Circuit::Input(PartyInput::A(x)) => num_a = *x,
        Circuit::Input(PartyInput::B(x)) => num_b = *x,
        Circuit::Gate(_, left, right) => {
            let (a0, b0) = get_number_of_inputs(left);
            let (a1, b1) = get_number_of_inputs(right);
            num_a = a0.max(a1);
            num_b = b0.max(b1);
        }
    }
    (num_a, num_b)
}




