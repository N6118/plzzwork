import dayjs from 'dayjs';

export const removeProp = (obj, propToDelete) =>
{
  for (let property in obj) {
    if (obj.hasOwnProperty(property)) {
      if (property === propToDelete) {
        delete obj[property];
      } else if (typeof obj[property] == 'object') {
        removeProp(obj[property], propToDelete);
      }
    }
  }
  return obj;
};

export const ifDateThenFormat = (str) =>
{
  if (dayjs(str)) {
    return dayjs(str).format('DD/MMM/YYYY');
  } else return str;
};