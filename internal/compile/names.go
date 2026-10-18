package compile

// The fake-name dictionary: every pairing of 64 first names and 64 last
// names, 4,096 in all, so a 12-bit index picks one. The names are common
// across Ireland, Britain and the countries their residents come from; none
// is meant to be anyone.
var (
	firstNames = [64]string{"Aoife", "Ciara", "Niamh", "Saoirse", "Siobhan", "Emma", "Sophie", "Grace", "Mary", "Anna",
		"Sarah", "Laura", "Rachel", "Hannah", "Chloe", "Ella", "Amelia", "Isla", "Zara", "Leah",
		"Fatima", "Mei", "Priya", "Olena", "Agnieszka", "Maria", "Lucia", "Ines", "Yasmin", "Amara",
		"Freya", "Ruth", "Sean", "Conor", "Cian", "Oisin", "Darragh", "Jack", "James", "Daniel",
		"Michael", "Patrick", "Liam", "Noah", "Adam", "Ryan", "Luke", "Eoin", "Fionn", "Tadhg",
		"Ronan", "Kevin", "David", "Thomas", "Piotr", "Lucas", "Mateo", "Arjun", "Wei", "Andrei",
		"Omar", "Tomas", "Kofi", "Diego"}
	lastNames = [64]string{"Murphy", "Kelly", "Sullivan", "Walsh", "Smith", "Brien", "Byrne", "Ryan", "Connor", "Neill",
		"Reilly", "Doyle", "McCarthy", "Gallagher", "Doherty", "Kennedy", "Lynch", "Murray", "Quinn", "Moore",
		"McLoughlin", "Carroll", "Connolly", "Daly", "Connell", "Wilson", "Dunne", "Brennan", "Burke", "Collins",
		"Campbell", "Clarke", "Johnston", "Hughes", "Farrell", "Fitzgerald", "Brown", "Martin", "Maguire", "Nolan",
		"Flynn", "Thompson", "Callaghan", "Duffy", "Mahony", "Boyle", "Healy", "Shea", "White", "Sweeney",
		"Hayes", "Kavanagh", "Power", "McGrath", "Moran", "Brady", "Stewart", "Casey", "Foley", "Nowak",
		"Silva", "Chen", "Patel", "Kowalski"}
)

// DictionarySize is the number of fake names.
const DictionarySize = len(firstNames) * len(lastNames)

// Names returns the dictionary in index order.
func Names() []string {
	out := make([]string, 0, DictionarySize)
	for _, f := range firstNames {
		for _, l := range lastNames {
			out = append(out, f+" "+l)
		}
	}
	return out
}
