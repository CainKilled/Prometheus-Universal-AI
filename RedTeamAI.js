
import React, { useState } from "react";
import { View, Text, Button, TextInput, StyleSheet, ScrollView } from "react-native";

const RedTeamAI = () => {
    const [command, setCommand] = useState("");
    const [output, setOutput] = useState("");

    const executeCommand = async () => {
        try {
            const response = await fetch("http://localhost:5000/metasploit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ command }),
            });
            const data = await response.json();
            setOutput(JSON.stringify(data, null, 2));
        } catch (error) {
            setOutput(`Error: ${error.message}`);
        }
    };

    return (
        <ScrollView style={styles.container}>
            <Text style={styles.title}>Red Team AI</Text>
            <TextInput
                style={styles.input}
                placeholder="Enter Command"
                value={command}
                onChangeText={setCommand}
            />
            <Button title="Run Command" onPress={executeCommand} />
            <Text style={styles.output}>{output}</Text>
        </ScrollView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        padding: 20,
        backgroundColor: "#121212",
    },
    title: {
        fontSize: 24,
        color: "#ffffff",
        textAlign: "center",
        marginBottom: 20,
    },
    input: {
        backgroundColor: "#1f1f1f",
        color: "#ffffff",
        padding: 10,
        marginBottom: 10,
        borderRadius: 5,
    },
    output: {
        backgroundColor: "#1f1f1f",
        color: "#ffffff",
        padding: 10,
        borderRadius: 5,
        marginTop: 20,
    },
});

export default RedTeamAI;
