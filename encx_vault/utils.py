from collections import OrderedDict

def print_table(entries, fields, max_cols=100, sep=' | '):
    fields = OrderedDict(fields)
    # Iterate to find the largest entries
    col_sizes = {field: len(str(label)) for field, label in fields.items()}
    for entry in entries:
        for field in fields:
            current_max = col_sizes.get(field, 0)
            col_sizes[field] = max(current_max, len(str(entry[field])))
    for field, size in col_sizes.items():
        col_sizes[field] = min(size, max_cols)

    number_of_seps = (len(fields) - 1)
    width = sum(col_sizes.values()) + (number_of_seps * len(sep))

    value_formats = ['{{:<{}}}'.format(col_sizes[field]) for field in fields.keys()]
    template = sep.join(value_formats)

    # Display header
    print(template.replace('<', '^').format(*fields.values()))
    print('-' * width)
    for entry in entries:
        values = [str(entry[field]) for field in fields.keys()]
        print(template.format(*values))
