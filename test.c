#include <stdio.h>

union myUnion {
    int intVal;
    int charVal;
    float floatVal;
};

int main() {
    union myUnion test;

    test.intVal = 1;
    printf("Après modification de intVal: %d\n", test.intVal);

    // Modifier charVal affectera les autres membres car ils partagent le même espace mémoire.
    test.charVal = 5;
    // L'affichage de intVal maintenant pourrait ne pas donner 1, car la mémoire a été réécrite par charVal.
    printf("Après modification de charVal, intVal devient: %d\n", test.intVal);
    // Note: l'effet exact dépend de la manière dont les données sont stockées et interprétées en mémoire.

    // De même pour floatVal.
    test.floatVal = 1.234;
    // Ceci écrase la mémoire partagée, affectant les valeurs de intVal et charVal.
    printf("Après modification de floatVal, intVal devient: %d et charVal devient: %c\n", test.intVal, test.charVal);

    return 0;
}

